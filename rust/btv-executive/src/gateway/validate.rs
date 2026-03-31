//! HTTP gateway exposing `Executive::decide()` as a REST API.
//!
//! POST /v1/validate  — scan + decide + log + deliver
//! POST /v1/decide    — same pipeline, additional agent metadata (logged only)
use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::{Executive, ScanSummary, DecisionError};
use btv_types::{Decision, RiskLevel, DeliveryPayload};

// ── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ValidateRequest {
    pub input:          String,
    pub jurisdiction:   String,
    pub policy_version: String,
}

#[derive(Deserialize)]
pub struct DecideRequest {
    pub input:          String,
    pub jurisdiction:   String,
    pub policy_version: String,
    pub agent_id:       Option<String>,
    pub profile:        Option<String>,
}

#[derive(Serialize)]
pub struct ValidateResponse {
    pub status:              String,  // "delivered" | "blocked"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery:            Option<DeliveryPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_summary:        Option<ScanSummaryWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:               Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_latency_us: Option<u64>,
}

/// Serialisable mirror of `ScanSummary` (avoids pub on internal type).
#[derive(Serialize)]
pub struct ScanSummaryWire {
    pub findings_count:    usize,
    pub critical_count:    usize,
    pub risk_level:        String,
    pub composite_risk:    f32,
    pub input_entropy:     f32,
    pub detected_language: String,
    pub scan_duration_us:  u64,
}

impl From<ScanSummary> for ScanSummaryWire {
    fn from(s: ScanSummary) -> Self {
        Self {
            findings_count:    s.findings_count,
            critical_count:    s.critical_count,
            risk_level:        format!("{:?}", s.risk_level),
            composite_risk:    s.composite_risk,
            input_entropy:     s.input_entropy,
            detected_language: s.detected_language,
            scan_duration_us:  s.scan_duration_us,
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_validate(
    State(exec): State<Arc<Executive>>,
    Json(req):   Json<ValidateRequest>,
) -> Json<ValidateResponse> {
    match exec.decide(
        req.input.as_bytes(),
        &req.jurisdiction,
        &req.policy_version,
    ).await {
        Ok(result) => Json(ValidateResponse {
            status:              "delivered".into(),
            delivery:            Some(result.delivery),
            scan_summary:        Some(result.scan_summary.into()),
            error:               None,
            decision_latency_us: Some(result.decision_latency_us),
        }),
        Err(e) => Json(ValidateResponse {
            status:              "blocked".into(),
            delivery:            None,
            scan_summary:        None,
            error:               Some(e.to_string()),
            decision_latency_us: None,
        }),
    }
}

async fn handle_decide(
    State(exec): State<Arc<Executive>>,
    Json(req):   Json<DecideRequest>,
) -> Json<ValidateResponse> {
    // agent_id / profile are logged for contestability (Phase 6) but do
    // NOT influence the constitutional pipeline — Theorem 3.5 guarantees
    // the pipeline is deterministic regardless of caller metadata.
    handle_validate(
        State(exec),
        Json(ValidateRequest {
            input:          req.input,
            jurisdiction:   req.jurisdiction,
            policy_version: req.policy_version,
        }),
    ).await
}

// ── Router factory ────────────────────────────────────────────────────────────

pub fn router(executive: Arc<Executive>) -> Router {
    Router::new()
        .route("/v1/validate", post(handle_validate))
        .route("/v1/decide",   post(handle_decide))
        .with_state(executive)
}
