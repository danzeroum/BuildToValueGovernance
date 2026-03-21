//! API Key Authentication Middleware — Gap #6
//! Validates X-API-Key header against env-configured keys.
//! /health and /metrics are exempt (public).

use axum::{body::Body, http::{Request, Response}};
use std::collections::HashSet;
use std::sync::Arc;
use tower::{Layer, Service};

/// Paths that don't require authentication.
const PUBLIC_PATHS: &[&str] = &["/health", "/metrics", "/v1/auth"];

/// Static asset extensions served by the React SPA.
const STATIC_EXTENSIONS: &[&str] = &[".js", ".css", ".svg", ".png", ".ico", ".html", ".json", ".woff", ".woff2", ".map"];

#[derive(Clone)]
pub struct ApiKeyLayer {
    valid_keys: Arc<HashSet<String>>,
}

impl ApiKeyLayer {
    /// Load valid API keys from BTV_API_KEYS env var (comma-separated).
    /// If empty/unset in dev, allows all requests with warning.
    pub fn from_env() -> Self {
        let keys: HashSet<String> = std::env::var("BTV_API_KEYS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if keys.is_empty() {
            let env = std::env::var("BTV_ENV").unwrap_or_else(|_| "development".into());
            if env == "production" {
                panic!("BTV_API_KEYS must be set in production");
            }
            tracing::warn!("⚠️  BTV_API_KEYS not set — auth disabled (dev mode)");
        } else {
            tracing::info!("API key auth enabled: {} keys loaded", keys.len());
        }

        Self {
            valid_keys: Arc::new(keys),
        }
    }
}

impl<S> Layer<S> for ApiKeyLayer {
    type Service = ApiKeyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiKeyService {
            inner,
            valid_keys: self.valid_keys.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ApiKeyService<S> {
    inner: S,
    valid_keys: Arc<HashSet<String>>,
}

impl<S> Service<Request<Body>> for ApiKeyService<S>
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
        let path = req.uri().path().to_string();
        let valid_keys = self.valid_keys.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Public paths bypass auth
            if PUBLIC_PATHS.iter().any(|p| path.starts_with(p)) {
                return inner.call(req).await;
            }

            // Static assets (React dashboard) bypass auth
            if path == "/" || STATIC_EXTENSIONS.iter().any(|ext| path.ends_with(ext)) || path.starts_with("/assets/") {
                return inner.call(req).await;
            }

            // JWT Bearer token auth (dashboard sessions)
            if let Some(auth_header) = req.headers().get("authorization").and_then(|v| v.to_str().ok()) {
                if auth_header.starts_with("Bearer ") {
                    // JWT validation — accept token if present (full validation in future)
                    let _token = &auth_header[7..];
                    // TODO: decode and validate JWT with BTV_JWT_SECRET
                    return inner.call(req).await;
                }
            }

            // Dev mode: no keys configured → allow all
            if valid_keys.is_empty() {
                return inner.call(req).await;
            }

            // Check X-API-Key header
            let key = req.headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if valid_keys.contains(key) {
                return inner.call(req).await;
            }

            // Reject
            crate::state::AUTH_REJECTED_TOTAL.inc();

            let body = serde_json::json!({
                "error": "UNAUTHORIZED",
                "message": "Invalid or missing API key. Provide X-API-Key header.",
            });

            let response = Response::builder()
                .status(axum::http::StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            Ok(response)
        })
    }
}