//! POST /v1/policy/test — Blind policy testing (Rawls)
//! Tests policy against input without knowing author/target/auditor.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

use buildtovalue_kernel::policy::{PolicyEngine, PolicyAction};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct PolicyTestRequest {
    pub policy_yaml: String,
    pub test_inputs: Vec<TestInput>,
}

#[derive(Deserialize)]
pub struct TestInput {
    pub input: String,
    pub label: String,
}

#[derive(Serialize)]
pub struct PolicyTestResponse {
    pub results: Vec<TestResult>,
    pub summary: TestSummary,
    pub blind_review: bool,
    pub latency_ms: f64,
}

#[derive(Serialize)]
pub struct TestResult {
    pub label: String,
    pub finding_count: u32,
    pub action: String,
    pub matched_rules: Vec<String>,
}

#[derive(Serialize)]
pub struct TestSummary {
    pub total: usize,
    pub blocked: usize,
    pub allowed: usize,
    pub logged: usize,
    pub fairness_score: f32,
}

pub async fn policy_test_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PolicyTestRequest>,
) -> Result<Json<PolicyTestResponse>, StatusCode> {
    let start = Instant::now();

    let mut engine = PolicyEngine::from_yaml_str(&req.policy_yaml)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut gk = state.gatekeeper.lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut results = Vec::new();
    let mut blocked = 0usize;
    let mut allowed = 0usize;
    let mut logged = 0usize;

    for test in &req.test_inputs {
        let evidence = gk.scan_for_evidence(&test.input, 0x0000);
        let findings: Vec<_> = evidence.get_all_findings();
        let eval = engine.evaluate_full(&test.input, &findings);

        let action_str = match eval.action {
            PolicyAction::Block => { blocked += 1; "BLOCK" }
            PolicyAction::Allow => { allowed += 1; "ALLOW" }
            PolicyAction::Log => { logged += 1; "LOG" }
            PolicyAction::Educate => { logged += 1; "EDUCATE" }
            PolicyAction::Redact => { logged += 1; "REDACT" }
        };

        results.push(TestResult {
            label: test.label.clone(),
            finding_count: evidence.finding_count as u32,
            action: action_str.to_string(),
            matched_rules: eval.matched_policies,
        });
    }

    let total = req.test_inputs.len();
    // Fairness: ratio of non-blocked to total (Rawls: minimize harm)
    let fairness_score = if total > 0 {
        (total - blocked) as f32 / total as f32
    } else {
        1.0
    };

    Ok(Json(PolicyTestResponse {
        results,
        summary: TestSummary {
            total,
            blocked,
            allowed,
            logged,
            fairness_score,
        },
        blind_review: true,
        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
    }))
}