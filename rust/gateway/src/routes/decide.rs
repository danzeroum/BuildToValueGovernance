//! POST /v1/decide — Pipeline ético completo (ADR-040).
//!
//! Alias semântico de /v1/validate com:
//! - Header X-BTV-Pipeline-Stage: ethical injetado no governance
//! - X-BTV-Jurisdiction → jurisdiction_bitmask (stub até ADR-032)
//! - Retorna explain_decision estruturado
//!
//! Filosofia: /v1/validate = scan técnico. /v1/decide = decisão ética.
//! Novos clientes devem usar /v1/decide. /v1/validate preservado para compat.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

use buildtovalue_kernel::policy::{PolicyEngine, PolicyAction};
use crate::state::AppState;

// ── JURISDICTION BITMASK (stub ADR-032) ──────────────────────

/// Converte header X-BTV-Jurisdiction em bitmask.
/// Valores: BR=0x01, US=0x02, EU=0x04, UK=0x08
/// TODO(ADR-032): mover para ScanContextFlags quando implementado.
fn parse_jurisdiction_bitmask(headers: &HeaderMap) -> u32 {
    let Some(val) = headers.get("X-BTV-Jurisdiction") else {
        return 0x01; // default: BR
    };
    let Ok(s) = val.to_str() else { return 0x01 };
    let mut mask: u32 = 0;
    for part in s.split(',') {
        match part.trim().to_uppercase().as_str() {
            "BR" => mask |= 0x01,
            "US" => mask |= 0x02,
            "EU" => mask |= 0x04,
            "UK" => mask |= 0x08,
            _    => {}
        }
    }
    if mask == 0 { 0x01 } else { mask }
}

// ── REQUEST / RESPONSE ────────────────────────────────────────

#[derive(Deserialize)]
pub struct DecideRequest {
    pub input: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Serialize)]
pub struct DecideResponse {
    pub action: String,
    pub original_action: String,
    pub mercy_applied: bool,
    pub finding_count: u32,
    pub critical_count: u32,
    pub composite_risk: f32,
    pub hard_blocked: bool,
    pub contestable: bool,
    pub appeal_deadline_hours: u32,
    pub verdict_id: String,
    pub signature: String,
    pub rationale: String,
    pub explain: ExplainDecision,
    pub jurisdiction_bitmask: u32,
    pub latency_ms: f64,
}

/// Justificativa estruturada (EU AI Act Art. 13).
#[derive(Serialize, Default)]
pub struct ExplainDecision {
    pub summary: String,
    pub rawls_rationale: String,
    pub levinas_rationale: String,
    pub jonas_rationale: String,
    pub gilligan_rationale: String,
    pub trust_score: f32,
    pub mercy_score: f32,
    pub pipeline_stages: Vec<String>,
}

// ── INTERNAL ─────────────────────────────────────────────────

const DEFAULT_POLICY: &str = include_str!("../../../../data/policies/core/default.yaml");

const FALLBACK_POLICY: &str = r#"
version: "1.0"
metadata:
  name: "Fallback"
  description: "Minimal fallback"
  created_at: "2026-01-01"
  updated_at: "2026-01-01"
  author: "System"
hard_blocks:
  - "DROP TABLE"
  - "<script>"
policies: []
"#;

#[derive(serde::Serialize)]
struct GovernanceDecideRequest {
    finding_count: u32,
    critical_count: u32,
    composite_risk: f32,
    action: String,
    hard_blocked: bool,
    matched_policies: Vec<String>,
    session_id: Option<String>,
    profile: Option<String>,
    agent_id: Option<String>,
    input_text: String,
    jurisdiction_bitmask: u32,
    pipeline_stage: String,
}

#[derive(serde::Deserialize, Default)]
struct GovernanceDecideVerdict {
    #[serde(default)] verdict_id: String,
    #[serde(default)] action: String,
    #[serde(default)] mercy_applied: bool,
    #[serde(default)] rationale: String,
    #[serde(default)] signature: String,
    #[serde(default)] contestable: bool,
    #[serde(default)] appeal_deadline_hours: u32,
    #[serde(default)] trust_score: f32,
    #[serde(default)] mercy_score: f32,
    #[serde(default)] explain: Option<GovernanceExplain>,
}

#[derive(serde::Deserialize, Default)]
struct GovernanceExplain {
    #[serde(default)] summary: String,
    #[serde(default)] rawls_rationale: String,
    #[serde(default)] levinas_rationale: String,
    #[serde(default)] jonas_rationale: String,
    #[serde(default)] gilligan_rationale: String,
    #[serde(default)] pipeline_trace: Vec<String>,
}

// ── HANDLER ───────────────────────────────────────────────────

pub async fn decide_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DecideRequest>,
) -> Result<Json<DecideResponse>, StatusCode> {
    let start = Instant::now();

    let jurisdiction_bitmask = parse_jurisdiction_bitmask(&headers);

    // ── EXECUTIVO ─────────────────────────────────────────────
    let (finding_count, critical_count, composite_risk, policy_action,
         hard_blocked, hard_block_term, matched_policies) = {
        let mut gk = state.gatekeeper.lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let session_id: u128 = req.session_id
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let evidence = gk.scan_for_evidence(&req.input, session_id);
        let findings = evidence.get_all_findings();

        let mut engine = PolicyEngine::from_yaml_str(DEFAULT_POLICY)
            .unwrap_or_else(|_| PolicyEngine::from_yaml_str(FALLBACK_POLICY).unwrap());
        let eval = engine.evaluate_full(&req.input, &findings);

        let action = match eval.action {
            PolicyAction::Block   => "BLOCK",
            PolicyAction::Redact  => "REDACT",
            PolicyAction::Educate => "EDUCATE",
            PolicyAction::Log     => "LOG",
            PolicyAction::Allow   => "ALLOW",
        };

        (
            evidence.finding_count as u32,
            evidence.critical_count as u32,
            evidence.composite_risk,
            action.to_string(),
            eval.hard_blocked,
            eval.hard_block_term,
            eval.matched_policies,
        )
    };

    // ── JUDICIÁRIO ────────────────────────────────────────────
    let verdict = {
        let governance_url = std::env::var("BTV_GOVERNANCE_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());

        let gov_req = GovernanceDecideRequest {
            finding_count,
            critical_count,
            composite_risk,
            action: policy_action.clone(),
            hard_blocked,
            matched_policies: matched_policies.clone(),
            session_id: req.session_id.clone(),
            profile: req.profile.clone(),
            agent_id: req.agent_id.clone(),
            input_text: req.input.clone(),
            jurisdiction_bitmask,
            pipeline_stage: "ethical".to_string(),
        };

        match state.http_client
            .post(format!("{}/v1/decide", governance_url))
            .header("X-BTV-Pipeline-Stage", "ethical")
            .json(&gov_req)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() =>
                r.json::<GovernanceDecideVerdict>().await.ok(),
            _ => None,
        }
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // ── MERGE ─────────────────────────────────────────────────
    let (final_action, mercy_applied, verdict_id, rationale, signature,
         contestable, appeal_hours, trust_score, mercy_score, explain) =
        if let Some(ref v) = verdict {
            let ex = v.explain.as_ref().map(|e| ExplainDecision {
                summary: e.summary.clone(),
                rawls_rationale: e.rawls_rationale.clone(),
                levinas_rationale: e.levinas_rationale.clone(),
                jonas_rationale: e.jonas_rationale.clone(),
                gilligan_rationale: e.gilligan_rationale.clone(),
                pipeline_stages: e.pipeline_trace.clone(),
                trust_score: v.trust_score,
                mercy_score: v.mercy_score,
            }).unwrap_or_default();
            (v.action.clone(), v.mercy_applied, v.verdict_id.clone(),
             v.rationale.clone(), v.signature.clone(), v.contestable,
             v.appeal_deadline_hours, v.trust_score, v.mercy_score, ex)
        } else {
            // Fail-secure: governance indisponível → manter policy action
            let ex = ExplainDecision {
                summary: "Governance unavailable — kernel decision applied".to_string(),
                rawls_rationale: "Policy applied uniformly (Rawls)".to_string(),
                levinas_rationale: "Fail-secure protects user (Levinas)".to_string(),
                jonas_rationale: "Responsibility preserved via audit trail (Jonas)".to_string(),
                gilligan_rationale: "No mercy without governance context (Gilligan)".to_string(),
                pipeline_stages: vec!["kernel".to_string(), "policy".to_string()],
                trust_score: 0.0,
                mercy_score: 0.0,
            };
            (policy_action.clone(), false, String::new(), String::new(),
             String::new(), !hard_blocked, if hard_blocked { 0 } else { 24 },
             0.0, 0.0, ex)
        };

    // ── METRICS ───────────────────────────────────────────────
    {
        use crate::state::*;
        DECISIONS_TOTAL.with_label_values(&[&final_action]).inc();
        DECIDE_TOTAL.with_label_values(&[&final_action]).inc();
        LATENCY_MS.observe(latency_ms);
        DECIDE_LATENCY_MS.observe(latency_ms);
        if mercy_applied { MERCY_APPLIED_TOTAL.inc(); }
        if hard_blocked  { HARD_BLOCKS_TOTAL.inc(); }
    }

    Ok(Json(DecideResponse {
        action: final_action,
        original_action: policy_action,
        mercy_applied,
        finding_count,
        critical_count,
        composite_risk,
        hard_blocked,
        contestable,
        appeal_deadline_hours: appeal_hours,
        verdict_id,
        signature,
        rationale,
        explain,
        jurisdiction_bitmask,
        latency_ms,
    }))
}
