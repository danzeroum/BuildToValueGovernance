//! Rate limiting middleware (ADR-040).
//!
//! v1.9: per-IP
//! v2.0: per-tenant (X-BTV-Tenant-Key → BLAKE3 hash, nunca valor original)
//!
//! Invariante: X-BTV-Tenant-Key nunca aparece em logs.
//! Hash BLAKE3 (16 chars hex) é usado como chave — sem reversibilidade.

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::{Layer, Service};
use std::task::{Context, Poll};
use std::future::Future;
use std::pin::Pin;

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
        RateLimitMiddleware {
            inner,
            max_requests: self.max_requests,
            window: self.window,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitMiddleware<S> {
    inner: S,
    max_requests: u32,
    window: Duration,
    buckets: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
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
            .map(|ip| format!("ip:{}", ip.split(',').next().unwrap_or("unknown").trim()))
            .unwrap_or_else(|| "ip:unknown".to_string())
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
        let window = self.window;

        let allowed = {
            let mut buckets = self.buckets.lock().unwrap();
            let now = Instant::now();
            let entry = buckets.entry(key.clone()).or_insert((0, now));

            if now.duration_since(entry.1) >= window {
                *entry = (1, now);
                true
            } else if entry.0 < max {
                entry.0 += 1;
                true
            } else {
                false
            }
        };

        if !allowed {
            RATE_LIMITED_TOTAL.inc();
            tracing::warn!("Rate limit exceeded for key prefix: {}",
                &key[..key.find(':').map(|i| i + 4).unwrap_or(key.len()).min(key.len())]);

            return Box::pin(async move {
                Ok((
                    StatusCode::TOO_MANY_REQUESTS,
                    [("Retry-After", "60"), ("X-RateLimit-Limit", "60")],
                    "Rate limit exceeded",
                ).into_response())
            });
        }

        let future = self.inner.call(req);
        Box::pin(async move { future.await })
    }
}
