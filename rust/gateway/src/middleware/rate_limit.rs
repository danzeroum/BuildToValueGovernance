//! Rate Limiting Middleware — Gap #9
//! Sliding window, per-IP, with Prometheus metrics.
//!
//! Design: tower Layer/Service pattern for Axum.
//! Default: 100 req/min per IP. Configurable via env.
//! Philosophy: Jonas — protect system resources proportionally.

use axum::{body::Body, http::{Request, Response}};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::{Layer, Service};

// ── CONFIG ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let max = std::env::var("BTV_RATE_LIMIT_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let window_secs = std::env::var("BTV_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        Self {
            max_requests: max,
            window: Duration::from_secs(window_secs),
        }
    }
}

// ── SLIDING WINDOW STATE ──────────────────────────────────────

#[derive(Clone)]
struct WindowEntry {
    timestamps: Vec<Instant>,
}

impl WindowEntry {
    fn new() -> Self {
        Self {
            timestamps: Vec::with_capacity(128),
        }
    }

    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.timestamps.retain(|t| *t > cutoff);
    }

    fn count(&self) -> u32 {
        self.timestamps.len() as u32
    }

    fn record(&mut self) {
        self.timestamps.push(Instant::now());
    }

    fn retry_after(&self, window: Duration) -> u64 {
        if let Some(oldest) = self.timestamps.first() {
            let elapsed = oldest.elapsed();
            if elapsed < window {
                return (window - elapsed).as_secs() + 1;
            }
        }
        0
    }
}

type WindowMap = Arc<Mutex<HashMap<String, WindowEntry>>>;

// ── LAYER ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RateLimitLayer {
    config: RateLimitConfig,
    windows: WindowMap,
}

impl RateLimitLayer {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            config: self.config.clone(),
            windows: self.windows.clone(),
        }
    }
}

// ── SERVICE ───────────────────────────────────────────────────

#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    config: RateLimitConfig,
    windows: WindowMap,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let config = self.config.clone();
        let windows = self.windows.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (allowed, remaining, retry_after) = {
                let mut map = windows.lock().unwrap_or_else(|e| e.into_inner());
                let entry = map.entry(ip.clone()).or_insert_with(WindowEntry::new);
                entry.prune(config.window);

                if entry.count() >= config.max_requests {
                    let retry = entry.retry_after(config.window);
                    (false, 0u32, retry)
                } else {
                    entry.record();
                    let remaining = config.max_requests - entry.count();
                    (true, remaining, 0)
                }
            };

            if !allowed {
                crate::state::RATE_LIMITED_TOTAL.inc();

                let body = serde_json::json!({
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": format!(
                        "Rate limit exceeded: {} requests per {} seconds",
                        config.max_requests,
                        config.window.as_secs()
                    ),
                    "retry_after_seconds": retry_after,
                });

                let response = Response::builder()
                    .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
                    .header("Content-Type", "application/json")
                    .header("Retry-After", retry_after.to_string())
                    .header("X-RateLimit-Limit", config.max_requests.to_string())
                    .header("X-RateLimit-Remaining", "0")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap();

                return Ok(response);
            }

            let mut response = inner.call(req).await?;
            let headers = response.headers_mut();
            headers.insert(
                "X-RateLimit-Limit",
                config.max_requests.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-RateLimit-Remaining",
                remaining.to_string().parse().unwrap(),
            );

            Ok(response)
        })
    }
}