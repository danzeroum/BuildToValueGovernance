//! Rate limiting middleware (ADR-040).
//!
//! v1.9: per-IP
//! v2.0: per-tenant (X-BTV-Tenant-Key → BLAKE3 hash, nunca valor original)
//!
//! MED-R03: buckets backed by `moka::sync::Cache` with TTL = window (60 s)
//! and max_capacity = 100 000. Entries are evicted automatically after the
//! window expires — no unbounded HashMap growth / OOM risk.
//!
//! MED-R02: `X-RateLimit-Remaining` now reflects the actual request count
//! within the current window (not the hardcoded literal "59").
//!
//! Invariante: X-BTV-Tenant-Key nunca aparece em logs.
//! Hash BLAKE3 (16 chars hex) é usado como chave — sem reversibilidade.

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use moka::sync::Cache;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Layer, Service};

use crate::state::RATE_LIMITED_TOTAL;

#[derive(Clone)]
pub struct RateLimitLayer {
    max_requests: u32,
    window: Duration,
}

impl RateLimitLayer {
    pub fn from_env() -> Self {
        let max = std::env::var("BTV_RATE_LIMIT_RPM")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        Self {
            max_requests: max,
            window: Duration::from_secs(60),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        // MED-R03: moka Cache with auto-eviction after `window` seconds and
        // an upper bound on entries (100_000) to cap memory consumption.
        // Cloning `Cache` is cheap — moka uses Arc internally, so all clones
        // share the same underlying shard map.
        let buckets: Cache<String, Arc<AtomicU32>> = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(self.window)
            .build();

        RateLimitMiddleware {
            inner,
            max_requests: self.max_requests,
            buckets,
        }
    }
}

#[derive(Clone)]
pub struct RateLimitMiddleware<S> {
    inner: S,
    max_requests: u32,
    /// MED-R03: moka Cache replaces HashMap + Mutex.
    /// Key  = BLAKE3-derived tenant token or "ip:…".
    /// Value = Arc<AtomicU32> request counter (reset on TTL expiry).
    buckets: Cache<String, Arc<AtomicU32>>,
}

impl<S> RateLimitMiddleware<S> {
    /// Extrai chave de rate limit.
    /// Prioridade: X-BTV-Tenant-Key (BLAKE3) > X-Forwarded-For > "unknown"
    /// INVARIANTE: valor do header nunca é logado.
    fn extract_key(req: &Request<Body>) -> String {
        if let Some(tenant) = req.headers().get("X-BTV-Tenant-Key") {
            if let Ok(val) = tenant.to_str() {
                let hash = blake3::hash(val.as_bytes());
                return format!("tenant:{}", &hash.to_hex()[..16]);
            }
        }
        req.headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .map(|ip| {
                format!(
                    "ip:{}",
                    ip.split(',').next().unwrap_or("unknown").trim()
                )
            })
            .unwrap_or_else(|| "ip:unknown".to_string())
    }

    /// Build a rate-limit response with accurate headers.
    /// `Response::builder()` with literal status and well-formed string
    /// headers cannot return Err — `unwrap_or_else` is a belt-and-suspenders
    /// fallback required by `clippy::unwrap_used`.
    fn rate_limit_response(limit: u32, remaining: u32, retry_after: u32) -> Response<Body> {
        let limit_s = limit.to_string();
        let remaining_s = remaining.to_string();
        let retry_s = retry_after.to_string();

        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("retry-after", retry_s.as_str())
            .header("x-ratelimit-limit", limit_s.as_str())
            .header("x-ratelimit-remaining", remaining_s.as_str())
            .body(Body::from("Rate limit exceeded"))
            .unwrap_or_else(|_| Response::new(Body::from("Rate limit exceeded")))
    }
}

impl<S> Service<Request<Body>> for RateLimitMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let key = Self::extract_key(&req);
        let max = self.max_requests;

        // MED-R03: moka entry() atomically gets or inserts the counter.
        // fetch_add returns the PREVIOUS value; +1 gives the new total.
        let count = {
            let entry = self.buckets
                .entry(key.clone())
                .or_insert_with(|| Arc::new(AtomicU32::new(0)));
            entry.value().fetch_add(1, Ordering::Relaxed) + 1
        };

        let allowed = count <= max;
        // MED-R02: actual remaining = max - count (saturating to avoid wrap).
        let remaining = max.saturating_sub(count);

        if !allowed {
            RATE_LIMITED_TOTAL.inc();
            let key_prefix = &key[..key
                .find(':')
                .map(|i| i + 4)
                .unwrap_or(key.len())
                .min(key.len())];
            tracing::warn!("Rate limit exceeded for key prefix: {key_prefix}");

            let resp = Self::rate_limit_response(max, 0, 60);
            return Box::pin(async move { Ok(resp) });
        }

        let future = self.inner.call(req);
        Box::pin(async move {
            let mut response = future.await?;

            // MED-R02: set headers with the actual remaining count.
            // HeaderValue::from_str on a u32 decimal string cannot fail;
            // fallbacks are belt-and-suspenders for clippy::unwrap_used.
            let limit_hv = axum::http::HeaderValue::from_str(&max.to_string())
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60"));
            let remaining_hv = axum::http::HeaderValue::from_str(&remaining.to_string())
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("0"));

            response.headers_mut().insert("x-ratelimit-limit", limit_hv);
            response.headers_mut().insert("x-ratelimit-remaining", remaining_hv);
            Ok(response)
        })
    }
}
