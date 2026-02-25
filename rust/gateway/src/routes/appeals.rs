//! /v1/appeals — Proxy para Python AppealEngine (ADR-037 + ADR-040).
//!
//! O gateway não implementa lógica de appeals — apenas proxeia para
//! Python governance (:8000). Fail-secure: se governance down → 503.
//!
//! Filosofia (Levinas): Contestabilidade é direito, não feature.
//! LGPD Art. 20 + EU AI Act Art. 14.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::Value;
use std::sync::Arc;

use crate::state::AppState;

fn governance_url() -> String {
    std::env::var("BTV_GOVERNANCE_URL")
        .unwrap_or_else(|_| "http://localhost:8000".to_string())
}

/// POST /v1/appeals — Submeter appeal.
pub async fn submit_appeal(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    let resp = state.http_client
        .post(format!("{}/v1/appeals/submit", governance_url()))
        .json(&body)
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let status = resp.status();
    let json: Value = resp.json().await
        .unwrap_or_else(|_| serde_json::json!({"error": "invalid response"}));

    if status.is_success() {
        use crate::state::APPEALS_SUBMITTED_TOTAL;
        APPEALS_SUBMITTED_TOTAL.inc();
        Ok(Json(json))
    } else {
        Err(StatusCode::from_u16(status.as_u16())
            .unwrap_or(StatusCode::BAD_GATEWAY))
    }
}

/// GET /v1/appeals/:id — Status do appeal.
pub async fn get_appeal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let resp = state.http_client
        .get(format!("{}/v1/appeals/{}", governance_url(), id))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    if resp.status().is_success() {
        let json: Value = resp.json().await
            .unwrap_or_else(|_| serde_json::json!({"error": "invalid response"}));
        Ok(Json(json))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// GET /v1/appeals/pending — Listar appeals pendentes.
pub async fn list_pending_appeals(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, StatusCode> {
    let resp = state.http_client
        .get(format!("{}/v1/appeals/pending", governance_url()))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let json: Value = resp.json().await
        .unwrap_or_else(|_| serde_json::json!({"error": "invalid response"}));
    Ok(Json(json))
}

/// POST /v1/appeals/:id/resolve — Resolver appeal (human-in-the-loop).
pub async fn resolve_appeal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    let resp = state.http_client
        .post(format!("{}/v1/appeals/{}/resolve", governance_url(), id))
        .json(&body)
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let status = resp.status();
    let json: Value = resp.json().await
        .unwrap_or_else(|_| serde_json::json!({"error": "invalid response"}));

    if status.is_success() {
        use crate::state::APPEALS_RESOLVED_TOTAL;
        APPEALS_RESOLVED_TOTAL.inc();
        Ok(Json(json))
    } else {
        Err(StatusCode::from_u16(status.as_u16())
            .unwrap_or(StatusCode::BAD_GATEWAY))
    }
}

/// GET /v1/appeals/metrics — SLA compliance metrics.
pub async fn appeals_metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, StatusCode> {
    let resp = state.http_client
        .get(format!("{}/v1/appeals/metrics", governance_url()))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let json: Value = resp.json().await
        .unwrap_or_else(|_| serde_json::json!({"error": "invalid response"}));
    Ok(Json(json))
}
