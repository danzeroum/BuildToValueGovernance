//! POST /v1/decide — Pipeline ético completo (ADR-040).
//! ADR-043: verdict_id gerado pelo Rust antes do scan, imutável até o cliente.
//!
//! v2.3.1: extract_client_ip, ip_risk_to_str, FALLBACK_POLICY moved to common.rs.

use axum::{
    extract::{Extension, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use ulid::Ulid;
use buildtovalue_kernel::policy::{PolicyEngine, PolicyAction};
use buildtovalue_kernel::core::types::{Action, EthicalVerdict};
use buildtovalue_kernel::ledger::entry::{ActionType, LedgerEntry};
use buildtovalue_kernel::evidence::TechnicalEvidence;
use crate::middleware::tenant_extractor::TenantId;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_policies: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default)]
#[allow(dead_code)]
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
    Extension(tenant_id): Extension<TenantId>,
    headers: HeaderMap,
    Json(req): Json<DecideRequest>,
) -> Result<axum::response::Response, StatusCode> {
    let start = Instant::now();

    let verdict_id = format!("VRD-{}", Ulid::new());

    // ── ADR-0083: derivar TEK do tenant ANTES de qualquer acesso ao ledger.
    // Se a derivação falhar (HKDF interno), retornar 500 — não vaza ledger.
    let tek = state.tenant_deriver
        .derive(tenant_id.as_str())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client_ip = extract_client_ip(&headers);
    let ip_class = state.ip_classifier.classify(&client_ip);
    let ip_risk_str = ip_risk_to_str(ip_class.risk).to_string();
    let ip_jurisdiction = state.jurisdiction_mapper.classify(&client_ip).country_code.to_string();

    let jurisdiction_bitmask = parse_jurisdiction_bitmask(&headers);

    // ── EXECUTIVO ─────────────────────────────────────────────
    // ADR-0083: `evidence` é movido para o escopo externo via tupla para
    // que possa ser apendado no ledger isolado do tenant após o Mutex
    // do Gatekeeper ser liberado.
    let (finding_count, critical_count, composite_risk, policy_action,
        hard_blocked, hard_block_term, matched_policies, max_finding_confidence,
        entropy, total_chars, blake3_hash, drift_level, evidence): (
        u32, u32, f32, String, bool, _, _, f32, f32, u32, String, String, TechnicalEvidence,
    ) = {
        let mut gk = state.gatekeeper.lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let session_id: u128 = req.session_id
            .as_deref()
            .map(|s| {
                let hash = blake3::hash(s.as_bytes());
                // [u8;32][..16].try_into() é invariante de tamanho fixo —
                // falha indica regressão de compilador, não erro de runtime.
                u128::from_le_bytes(
                    hash.as_bytes()[..16]
                        .try_into()
                        .unwrap_or_else(|_| panic!("BTV invariant violation: blake3 slice [..16] into [u8;16]"))
                )
            })
            .unwrap_or(0);

        let evidence = gk.scan_for_evidence(&req.input, session_id);
        let findings = evidence.get_all_findings();

        let engine_result = PolicyEngine::from_yaml_str(DEFAULT_POLICY)
            .or_else(|_| PolicyEngine::from_yaml_str(FALLBACK_POLICY));
        let mut engine = match engine_result {
            Ok(e) => e,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
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
            evidence,
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

    // ── AUDITIVO: Ledger JSONL (dev tooling, agora por tenant) ────
    {
        use std::io::Write;
        let log_line = format!(
            "{{\"ts\":{},\"tenant\":\"{}\",\"session\":\"{}\",\"profile\":\"{}\",\"policy_action\":\"{}\",\"final_action\":\"{}\",\"mercy\":{},\"risk\":{:.4},\"findings\":{},\"critical\":{},\"hard_blocked\":{},\"verdict_id\":\"{}\",\"latency_ms\":{:.2}}}\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            tenant_id.as_str(),
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
        let dir = format!("data/ledger/{}", tenant_id.as_str());
        let path = format!("{}/decisions.jsonl", dir);
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(log_line.as_bytes());
        }
    }

    // ── ADR-0083: persistir binary LedgerEntry no ledger isolado do tenant.
    // Falhas de I/O no ledger NÃO devem bloquear a resposta (apenas logam),
    // pois a decisão já foi tomada e o JSONL acima já serve como fallback.
    let (entry_id, decision_id_u128) = build_and_append_tenant_entry(
        &state,
        tenant_id.as_str(),
        tek.as_ref(),
        &evidence,
        &policy_action,
        &final_action,
    )
    .await
    .unwrap_or((0, evidence.audit_trail_id));

    let _ = entry_id;

    // ── ADR-0084: headers de auditoria na resposta HTTP.
    let mut response_headers = HeaderMap::new();
    // X-BTV-Decision-Id: liga resposta à entrada do ledger forense (UUID v7).
    if let Ok(val) = HeaderValue::from_str(&format!("{:032x}", decision_id_u128)) {
        response_headers.insert(HeaderName::from_static("x-btv-decision-id"), val);
    }
    // X-BTV-Verdict-Signature: HMAC-SHA256(TEK, verdict_id) — autenticidade.
    let sig_payload = final_verdict_id.as_bytes();
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    if let Ok(mut mac) = <Hmac<Sha256>>::new_from_slice(tek.as_ref()) {
        mac.update(sig_payload);
        let sig_hex = hex::encode(mac.finalize().into_bytes());
        if let Ok(val) = HeaderValue::from_str(&format!("hmac-sha256={sig_hex}")) {
            response_headers.insert(HeaderName::from_static("x-btv-verdict-signature"), val);
        }
    }
    response_headers.insert(
        HeaderName::from_static("x-btv-sampling-mode"),
        HeaderValue::from_static("full"),
    );

    let body = Json(DecideResponse {
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
    });

    Ok((response_headers, body).into_response())
}

/// Constrói um `LedgerEntry` a partir da decisão e o persiste no ledger
/// isolado do tenant via `DurableLedger::append_with_key`. Retorna
/// `(entry_id, audit_trail_id)`. Em caso de falha de I/O do ledger,
/// retorna `Err(())` para o caller decidir fallback (decisão não bloqueia).
async fn build_and_append_tenant_entry(
    state: &Arc<AppState>,
    tenant_id: &str,
    tek: &[u8],
    evidence: &TechnicalEvidence,
    policy_action: &str,
    final_action: &str,
) -> Result<(u64, u128), ()> {
    let ledger = state.tenant_router.route(tenant_id).await.map_err(|e| {
        tracing::warn!("tenant_router.route failed for '{tenant_id}': {e}");
    })?;

    let action_enum = match policy_action {
        "BLOCK"   => Action::Block,
        "REDACT"  => Action::Redact,
        "EDUCATE" => Action::Log,
        "LOG"     => Action::Log,
        _         => Action::Allow,
    };
    let verdict_enum = match final_action {
        "BLOCK"   => EthicalVerdict::Block,
        "REDACT"  => EthicalVerdict::Redact,
        "EDUCATE" => EthicalVerdict::Educate,
        "REPORT"  => EthicalVerdict::Report,
        "ALLOW"   => EthicalVerdict::Allow,
        _         => EthicalVerdict::Pending,
    };

    let mut entry = LedgerEntry {
        audit_trail_id: evidence.audit_trail_id,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        action: ActionType::from(action_enum),
        ethical_verdict: verdict_enum,
        ..LedgerEntry::default()
    };
    entry.risk_level = if evidence.composite_risk >= 80.0 {
        buildtovalue_kernel::core::types::RiskLevel::Critical
    } else if evidence.composite_risk >= 60.0 {
        buildtovalue_kernel::core::types::RiskLevel::High
    } else if evidence.composite_risk >= 30.0 {
        buildtovalue_kernel::core::types::RiskLevel::Low
    } else {
        buildtovalue_kernel::core::types::RiskLevel::Safe
    };

    let entry_id = ledger
        .append_with_key(entry, evidence, tek)
        .map_err(|e| {
            tracing::warn!("ledger.append_with_key failed for '{tenant_id}': {e}");
        })?;

    Ok((entry_id, evidence.audit_trail_id))
}
