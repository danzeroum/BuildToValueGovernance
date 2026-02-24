//! Route definitions.
pub mod validate;
pub mod health;
pub mod metrics;
pub mod blind_review;
pub mod sanitize;
pub mod guard;

use std::sync::Arc;
use axum::{Router, routing::{get, post}, middleware};
use tower_http::trace::TraceLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::cors::{CorsLayer, Any};
use std::time::Duration;
use crate::state::AppState;
use crate::middleware::rate_limit::RateLimitLayer;
use crate::middleware::auth::ApiKeyLayer;
use crate::middleware::trace_propagation::trace_propagation;

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/v1/validate", post(validate::validate_handler))
        .route("/v1/sanitize", post(sanitize::sanitize_handler))
        .route("/v1/policy/test", post(blind_review::policy_test_handler))
        .route("/health", get(health::health_handler))
        .route("/metrics", get(metrics::metrics_handler))
        .route("/v1/guard", post(guard::guard_handler))
        .layer(ApiKeyLayer::from_env())
        .layer(RateLimitLayer::from_env())
        .layer(middleware::from_fn(trace_propagation))
        .layer(cors)
        .layer(TimeoutLayer::new(Duration::from_secs(20)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}