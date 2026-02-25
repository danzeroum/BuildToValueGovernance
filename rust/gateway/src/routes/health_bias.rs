//! GET /health/bias — BiasGuardian status (ADR-036 + ADR-040).
//!
//! Expõe divergência FPR/FNR declarado vs medido em tempo real.
//! Se governance indisponível → bias_ok: false (fail-secure).
//!
//! Filosofia (Jonas): Responsabilidade exige que o sistema declare
//! publicamente quando suas declarações de viés estão desatualizadas.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

#[derive(Serialize)]
pub struct BiasHealthResponse {
    pub bias_ok: bool,
    pub governance_reachable: bool,
    pub details: Option<BiasDetails>,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct BiasDetails {
    #[serde(default)]
    pub validator_id: String,
    #[serde(default)]
    pub declared_fnr_pct: f32,
    #[serde(default)]
    pub measured_fnr_pct: f32,
    #[serde(default)]
    pub divergence_pct: f32,
    #[serde(default)]
    pub level: String, // OK | WARNING | BLOCK
    #[serde(default)]
    pub calibration_age_days: u32,
    #[serde(default)]
    pub calibration_expired: bool,
}

pub async fn health_bias_handler(
    State(state): State<Arc<AppState>>,
) -> Json<BiasHealthResponse> {
    let governance_url = std::env::var("BTV_GOVERNANCE_URL")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());

    match state.http_client
        .get(format!("{}/v1/bias/status", governance_url))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>().await {
                Ok(json) => {
                    let bias_ok = json.get("bias_ok")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let details = serde_json::from_value::<BiasDetails>(json)
                        .ok();

                    let message = if bias_ok {
                        "BiasDeclaration within thresholds (ADR-036)".to_string()
                    } else {
                        "BiasDeclaration divergence detected — review required".to_string()
                    };

                    Json(BiasHealthResponse {
                        bias_ok,
                        governance_reachable: true,
                        details,
                        message,
                    })
                }
                Err(_) => Json(BiasHealthResponse {
                    bias_ok: false,
                    governance_reachable: true,
                    details: None,
                    message: "Invalid response from governance".to_string(),
                }),
            }
        }
        _ => Json(BiasHealthResponse {
            bias_ok: false,
            governance_reachable: false,
            details: None,
            message: "Governance unreachable — bias status unknown (fail-secure: false)".to_string(),
        }),
    }
}
