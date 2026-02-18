//! POST /v1/sanitize — Mask PII in LLM output.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

use buildtovalue_kernel::security::output_guard::OutputGuard;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SanitizeRequest {
    pub text: String,
}

#[derive(Serialize)]
pub struct SanitizeResponse {
    pub original_length: u32,
    pub sanitized_text: String,
    pub masked_count: u32,
    pub masked_types: Vec<String>,
    pub latency_ms: f64,
}

pub async fn sanitize_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SanitizeRequest>,
) -> Result<Json<SanitizeResponse>, StatusCode> {
    let start = Instant::now();

    let guard = OutputGuard::new();
    let result = guard.mask_pii(&req.text);
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // ── METRICS ───────────────────────────────────────────────
    {
        use crate::state::*;
        SANITIZE_TOTAL.inc();
        for t in &result.masked_types {
            SANITIZE_MASKED_TOTAL.with_label_values(&[t]).inc();
        }
    }

    Ok(Json(SanitizeResponse {
        original_length: req.text.len() as u32,
        sanitized_text: result.sanitized_text,
        masked_count: result.masked_count,
        masked_types: result.masked_types,
        latency_ms,
    }))
}