//! GET /v1/trust/:session — Trust score proxy (ADR-039 + ADR-040).
//!
//! INVARIANTE (ADR-039): session_id nunca é o user_id real.
//! O gateway não valida isso — é responsabilidade do cliente.
//! Privacy-preserving: session_id é opaco para o gateway.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::Value;
use std::sync::Arc;

use crate::state::AppState;

/// GET /v1/trust/:session_id — Retorna trust score atual.
pub async fn get_trust_handler(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let governance_url = std::env::var("BTV_GOVERNANCE_URL")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());

    let resp = state.http_client
        .get(format!("{}/v1/trust/{}", governance_url, session_id))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    if resp.status().is_success() {
        let json: Value = resp.json().await
            .unwrap_or_else(|_| serde_json::json!({"error": "invalid response"}));
        Ok(Json(json))
    } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
        Err(StatusCode::NOT_FOUND)
    } else {
        Err(StatusCode::BAD_GATEWAY)
    }
}
