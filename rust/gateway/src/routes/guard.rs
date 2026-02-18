//! POST /v1/guard — Sanitize LLM output before returning to user.
//! P0: OutputGuard automático no response path.
//!
//! Filosofia (Levinas): Proteger o usuário contra vazamento de PII
//! na resposta do LLM, mesmo que o LLM tenha sido instruído a não fazê-lo.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

use buildtovalue_kernel::output_guard::OutputSanitizer;
use buildtovalue_kernel::security::output_guard::OutputGuard;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct GuardRequest {
    /// LLM response text to sanitize
    pub text: String,
    /// Optional: session ID for audit trail
    #[serde(default)]
    pub session_id: Option<String>,
    /// Optional: also scan for XSS/injection (default: true)
    #[serde(default = "default_true")]
    pub xss_protection: bool,
    /// Optional: re-scan after masking (default: true)
    #[serde(default = "default_true")]
    pub rescan: bool,
}

fn default_true() -> bool { true }

#[derive(Serialize)]
pub struct GuardResponse {
    /// Sanitized text (PII masked, XSS stripped)
    pub text: String,
    /// Number of PII masks applied
    pub pii_masked: u32,
    /// Types of PII masked
    pub masked_types: Vec<String>,
    /// XSS/injection patterns found and stripped
    pub xss_patterns_found: Vec<String>,
    /// Whether re-scan confirmed clean output
    pub rescan_clean: bool,
    /// Processing latency
    pub latency_ms: f64,
    /// Whether any modification was made
    pub modified: bool,
}

pub async fn guard_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<GuardRequest>,
) -> Json<GuardResponse> {
    let start = Instant::now();

    // Stage 1: XSS/injection sanitization
    let (xss_clean, xss_patterns) = if req.xss_protection {
        let guard = OutputGuard::new();
        let analysis = guard.analyze_content(&req.text);
        let cleaned = if analysis.requires_sanitization {
            guard.sanitize_text(&req.text)
        } else {
            req.text.clone()
        };
        (cleaned, analysis.dangerous_patterns_found)
    } else {
        (req.text.clone(), Vec::new())
    };

    // Stage 2: PII masking
    let sanitizer = OutputSanitizer::new();
    let pii_result = sanitizer.sanitize(&xss_clean);

    let modified = pii_result.masks_applied > 0 || !xss_patterns.is_empty();

    if modified {
        log::info!(
            "OutputGuard: {} PII masked, {} XSS patterns stripped (session: {})",
            pii_result.masks_applied,
            xss_patterns.len(),
            req.session_id.as_deref().unwrap_or("unknown"),
        );
    }

    // Stage 3: Metrics
    {
        use crate::state::*;
        SANITIZE_TOTAL.inc();
        for detail in &pii_result.mask_details {
            SANITIZE_MASKED_TOTAL
                .with_label_values(&[detail.pii_type])
                .inc();
        }
    }

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    Json(GuardResponse {
        text: pii_result.output,
        pii_masked: pii_result.masks_applied,
        masked_types: pii_result.mask_details
            .iter()
            .map(|d| d.pii_type.to_string())
            .collect(),
        xss_patterns_found: xss_patterns,
        rescan_clean: pii_result.rescan_clean,
        latency_ms,
        modified,
    })
}