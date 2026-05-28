//! Route definitions — BTV Gateway v2.0 (ADR-040).
//!
//! Rotas v1.9 (preservadas):
//!   POST /v1/validate, /v1/sanitize, /v1/policy/test, /v1/guard
//!   GET  /health, /metrics
//!
//! Rotas v2.0 (novas — ADR-040):
//!   POST /v1/decide           — alias ético de /v1/validate
//!   POST /v1/appeals          — proxy AppealEngine (ADR-037)
//!   GET  /v1/appeals/:id
//!   GET  /v1/appeals/pending
//!   POST /v1/appeals/:id/resolve
//!   GET  /v1/appeals/metrics
//!   GET  /health/bias         — BiasGuardian (ADR-036)
//!   GET  /v1/trust/:session   — TrustScore (ADR-039)
//!
//! v2.3.1: Added `common` module (extract_client_ip, ip_risk_to_str, FALLBACK_POLICY)
//!   to eliminate duplication between validate.rs and decide.rs.

pub mod common;   // v2.3.1: shared helpers — import before route modules
pub mod validate;
pub mod health;
pub mod metrics;
pub mod blind_review;
pub mod sanitize;
pub mod guard;
pub mod decide;       // ADR-040
pub mod appeals;      // ADR-040
pub mod health_bias;  // ADR-040
pub mod trust;        // ADR-040
pub mod proxy;        // Fase 2: proxy HTTP transparente (ADR-0059)

use std::sync::Arc;
use axum::{Router, routing::{any, get, post}, middleware};
use tower_http::trace::TraceLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::cors::{CorsLayer, Any};
use tower_http::services::{ServeDir, ServeFile};
use std::time::Duration;
use crate::state::AppState;
use crate::middleware::rate_limit::RateLimitLayer;
use crate::middleware::auth::ApiKeyLayer;
use crate::middleware::trace_propagation::trace_propagation;
use crate::middleware::tenant_extractor::TenantExtractorLayer;

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // ── Rotas v1.9 (inalteradas) ──────────────────────────
        .route("/v1/validate",              post(validate::validate_handler))
        .route("/v1/sanitize",              post(sanitize::sanitize_handler))
        .route("/v1/policy/test",           post(blind_review::policy_test_handler))
        .route("/v1/guard",                 post(guard::guard_handler))
        .route("/health",                   get(health::health_handler))
        .route("/metrics",                  get(metrics::metrics_handler))

        // ── Rotas v2.0 (ADR-040) ──────────────────────────────
        .route("/v1/decide",                post(decide::decide_handler))

        // Appeals proxy (ADR-037)
        .route("/v1/appeals",               post(appeals::submit_appeal))
        .route("/v1/appeals/pending",       get(appeals::list_pending_appeals))
        .route("/v1/appeals/metrics",       get(appeals::appeals_metrics))
        .route("/v1/appeals/:id",           get(appeals::get_appeal))
        .route("/v1/appeals/:id/resolve",   post(appeals::resolve_appeal))

        // BiasGuardian health (ADR-036)
        .route("/health/bias",              get(health_bias::health_bias_handler))

        // Trust score (ADR-039)
        .route("/v1/trust/:session",        get(trust::get_trust_handler))

        // ── Proxy HTTP transparente (ADR-0059) ───────────────────
        // Drop-in: OPENAI_BASE_URL=http://gateway:8080/v1/proxy
        // ApiKeyLayer protege a rota; Authorization do LLM provider é forwarded.
        .route("/v1/proxy/*path",           any(proxy::proxy_forward))

        // ── SPA fallback (React dashboard) ──────────────────────
        .fallback_service(
            ServeDir::new("./dashboard/dist")
                .not_found_service(ServeFile::new("./dashboard/dist/index.html"))
        )

        // ── Layers (ordem preservada) ─────────────────────────
        // ADR-0084: TenantExtractor APÓS ApiKey (auth deve passar antes da
        // extração de tenant). Layers no Axum executam na ordem inversa de
        // declaração, então ApiKey é declarado depois para rodar primeiro.
        .layer(TenantExtractorLayer::from_env())
        .layer(ApiKeyLayer::from_env())
        .layer(RateLimitLayer::from_env())
        .layer(middleware::from_fn(trace_propagation))
        .layer(cors)
        .layer(TimeoutLayer::new(Duration::from_secs(20)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
