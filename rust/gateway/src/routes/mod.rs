//! Route definitions.
pub mod validate;
pub mod health;
pub mod metrics;
mod policy_test;
mod sanitize;

use std::sync::Arc;
use axum::{Router, routing::{get, post}};
use tower_http::trace::TraceLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::cors::{CorsLayer, Any};
use std::time::Duration;
use crate::state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/v1/validate", post(validate::validate_handler))
        .route("/v1/sanitize", post(sanitize::sanitize_handler))
        .route("/v1/policy/test", post(policy_test::policy_test_handler))
        .route("/health", get(health::health_handler))
        .route("/metrics", get(metrics::metrics_handler))
        .layer(cors)
        .layer(TimeoutLayer::new(Duration::from_millis(5000)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}