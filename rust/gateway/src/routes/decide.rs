//! POST /v1/decide — Pipeline ético completo (ADR-040).
//! ADR-043: verdict_id gerado pelo Rust antes do scan, imutável até o cliente.
//!
//! v2.3.1: extract_client_ip, ip_risk_to_str, FALLBACK_POLICY moved to common.rs.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use ulid::Ulid;
use buildtovalue_kernel::policy::{PolicyEngine, PolicyAction};
use crate::state::AppState;
use super::common::{extract_client_ip, ip_risk_to_str, FALLBACK_POLICY};

// ── JURISDICTION BITMASK (stub ADR-032) ──────────────────────

fn parse_jurisdiction_bitmask(headers: &HeaderMap) -> u32 {
    let Some(val) = headers.get("X-BTV-Jurisdiction") else {
        return 0x01;
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
    /// Input modality: "text" | "visual" | "audio". Activates corresponding guard modules.
    #[serde(default)]
    pub source: Option<String>,
    /// Channel through which the request arrived (e.g. "whatsapp_2fa", "email", "app_biometric").
    /// Used by ChannelAuthorityVerifier to enforce pa_channel_hierarchy.yaml.
    #[serde(default)]
    pub channel: Option<String>,
    /// Names of agents/*.yaml policy files to activate for this request.
    /// Example: ["pa_channel_hierarchy", "pa_p2p_oracle"]. Vec allocates only during
    /// serde deserialization (outside Rust kernel hot path — see ADR discussion Complement E).
    #[serde(default)]
    pub agent_policies: Option<Vec<String>>,
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
    // campos adicionados para X-Ray
    pub trust_score: f32,
    pub mercy_score: f32,
    pub mercy_scenario: String,
    pub risk_classification: String,
    pub entropy: f32,
    pub ip_risk: String,
    pub ip_jurisdiction: String,
    pub drift_level: String,
}

#[derive(Serialize, Deserialize, Default)]
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
    verdict_id: String,
    max_finding_confidence: f32,
    entropy: f32,
    total_chars: u32,
    blake3_hash: String,
    ip_risk: String,
    ip_jurisdiction: String,
    drift_level: String,
    /// Forwarded from DecideRequest — input modality (ADR policy-activation)
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    /// Forwarded from DecideRequest — channel identifier (ADR policy-activation)
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    /// Forwarded from DecideRequest — agent YAML policy names to activate
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_policies: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default)]
#[allow(dead_code)] // Fields populated from Python governance response
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
    #[serde(default)] mercy_scenario: String,
    #[serde(default)] risk_classification: String,
    #[serde(default)] entropy: f32,
    #[serde(default)] ip_risk: String,
    #[serde(default)] ip_jurisdiction: String,
    #[serde(default)] drift_level: String,
    #[serde(default)] explain: Option<GovernanceExplain>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
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

    let verdict_id = format!("VRD-{}", Ulid::new());

    let client_ip = extract_client_ip(&headers);
    let ip_class = state.ip_classifier.classify(&client_ip);
    let ip_risk_str = ip_risk_to_str(ip_class.risk).to_string();
    let ip_jurisdiction = state.jurisdiction_mapper.classify(&client_ip).country_code.to_string();

    let jurisdiction_bitmask = parse_jurisdiction_bitmask(&headers);

    // ── EXECUTIVO ─────────────────────────────────────────────
    let (finding_count, critical_count, composite_risk, policy_action,
        hard_blocked, hard_block_term, matched_policies, max_finding_confidence,
        entropy, total_chars, blake3_hash, drift_level) = {
        let mut gk = state.gatekeeper.lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let session_id: u128 = req.session_id
            .as_deref()
            .map(|s| {
                let hash = blake3::hash(s.as_bytes());
                u128::from_le_bytes(hash.as_bytes()[..16].try_into().unwrap())
            })
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

        let max_conf = findings.iter()
            .map(|f| f.confidence as f32 / 255.0)
            .fold(0.0_f32, f32::max);

        let drift_str = if let Ok(mut tracker) = state.session_tracker.lock() {
            let sid: u128 = req.session_id.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0);
            let result = tracker.track(sid, &evidence);
            match result.level {
                buildtovalue_kernel::session_guard::DriftLevel::None     => "None",
                buildtovalue_kernel::session_guard::DriftLevel::Low      => "LOW",
                buildtovalue_kernel::session_guard::DriftLevel::Medium   => "MEDIUM",
                buildtovalue_kernel::session_guard::DriftLevel::High     => "HIGH",
                buildtovalue_kernel::session_guard::DriftLevel::Critical => "CRITICAL",
            }.to_string()
        } else { "None".to_string() };

        (
            evidence.finding_count as u32,
            evidence.critical_count as u32,
            evidence.composite_risk,
            action.to_string(),
            eval.hard_blocked,
            eval.hard_block_term,
            eval.matched_policies,
            max_conf,
            evidence.stats.entropy,
            evidence.stats.total_chars,
            format!("{:016x}", evidence.original_request_hash),
            drift_str,
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
            verdict_id: verdict_id.clone(),
            max_finding_confidence,
            entropy,
            total_chars,
            blake3_hash: blake3_hash.clone(),
            ip_risk: ip_risk_str.clone(),
            ip_jurisdiction: ip_jurisdiction.clone(),
            drift_level: drift_level.clone(),
            source: req.source.clone(),
            channel: req.channel.clone(),
            agent_policies: req.agent_policies.clone(),
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
    let (final_action, mercy_applied, final_verdict_id, rationale, signature,
        contestable, appeal_hours, trust_score, mercy_score,
        mercy_scenario, risk_classification, explain) =
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
            (
                v.action.clone(),
                v.mercy_applied,
                if v.verdict_id.is_empty() { verdict_id.clone() } else { v.verdict_id.clone() },
                v.rationale.clone(),
                v.signature.clone(),
                v.contestable,
                v.appeal_deadline_hours,
                v.trust_score,
                v.mercy_score,
                v.mercy_scenario.clone(),
                v.risk_classification.clone(),
                ex,
            )
        } else {
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
            (
                policy_action.clone(),
                false,
                verdict_id.clone(),
                String::new(),
                String::new(),
                !hard_blocked,
                if hard_blocked { 0 } else { 24 },
                0.0_f32,
                0.0_f32,
                String::new(),
                String::new(),
                ex,
            )
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

    let _ = hard_block_term;
    let _ = max_finding_confidence;

    // ── AUDITIVO: Ledger JSONL ────────────────────────────────
    {
        use std::io::Write;
        let log_line = format!(
            "{{\"ts\":{},\"session\":\"{}\",\"profile\":\"{}\",\"policy_action\":\"{}\",\"final_action\":\"{}\",\"mercy\":{},\"risk\":{:.4},\"findings\":{},\"critical\":{},\"hard_blocked\":{},\"verdict_id\":\"{}\",\"latency_ms\":{:.2}}}\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            req.session_id.as_deref().unwrap_or("0"),
            req.profile.as_deref().unwrap_or("default"),
            policy_action,
            final_action,
            mercy_applied,
            composite_risk,
            finding_count,
            critical_count,
            hard_blocked,
            final_verdict_id,
            latency_ms,
        );
        let _ = std::fs::create_dir_all("data/ledger");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("data/ledger/decisions.jsonl")
        {
            let _ = f.write_all(log_line.as_bytes());
        }
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
        verdict_id: final_verdict_id,
        signature,
        rationale,
        explain,
        jurisdiction_bitmask,
        latency_ms,
        trust_score,
        mercy_score,
        mercy_scenario,
        risk_classification,
        entropy,
        ip_risk: ip_risk_str,
        ip_jurisdiction,
        drift_level,
    }))
}