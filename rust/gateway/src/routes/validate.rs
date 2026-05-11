//! POST /v1/validate — Scan + Policy + Governance (República Algorítmica).
//! Gap #4: Profile-aware governance (sector whitelist via Python).
//! ADR-043: verdict_id gerado pelo Rust antes do scan, imutável até o cliente.
//!
//! v2.3.1: extract_client_ip, ip_risk_to_str, FALLBACK_POLICY moved to common.rs.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use ulid::Ulid;
use buildtovalue_kernel::policy::{PolicyEngine, PolicyAction};
use crate::state::AppState;
use super::common::{extract_client_ip, ip_risk_to_str, FALLBACK_POLICY};

// ── REQUEST / RESPONSE ────────────────────────────────────────

#[derive(Deserialize)]
pub struct ValidateRequest {
    pub input: String,
    #[serde(default)]
    pub session_id: Option<String>,
    /// Profile ID (e.g. "medical", "financial"). Forwarded to Python governance.
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Serialize)]
pub struct ValidateResponse {
    pub finding_count: u32,
    pub critical_count: u32,
    pub composite_risk: f32,
    pub action: String,
    pub original_action: String,
    pub mercy_applied: bool,
    pub latency_ms: f64,
    pub contestable: bool,
    pub appeal_deadline_hours: u32,
    pub message: String,
    pub hard_blocked: bool,
    pub matched_policies: Vec<String>,
    pub verdict_id: String,
    pub signature: String,
    pub rationale: String,
}

// ── INTERNAL TYPES ────────────────────────────────────────────

const DEFAULT_POLICY: &str = include_str!("../../../../data/policies/core/default.yaml");

#[derive(Serialize)]
struct GovernanceRequest {
    finding_count: u32,
    critical_count: u32,
    composite_risk: f32,
    action: String,
    hard_blocked: bool,
    matched_policies: Vec<String>,
    session_id: Option<String>,
    /// Profile forwarded for sector whitelist + mercy adjustment.
    profile: Option<String>,
    /// Full input text for sector trigger matching (Opção A).
    input_text: String,
    /// ADR-043: ID gerado pelo Rust, passado ao Python para uso sem modificação.
    verdict_id: String,
    /// Confiança máxima entre findings (0.0-1.0).
    max_finding_confidence: f32,
    entropy: f32,
    total_chars: u32,
    blake3_hash: String,
    /// ADR-044: contexto de rede e sessão
    ip_risk: String,
    ip_jurisdiction: String,
    drift_level: String,
}

#[derive(Deserialize, Default)]
struct GovernanceVerdict {
    #[serde(default)]
    verdict_id: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    mercy_applied: bool,
    #[serde(default)]
    rationale: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    contestable: bool,
    #[serde(default)]
    appeal_deadline_hours: u32,
}

struct ScanResult {
    finding_count: u32,
    critical_count: u32,
    composite_risk: f32,
    policy_action: String,
    hard_blocked: bool,
    hard_block_term: Option<String>,
    matched_policies: Vec<String>,
    max_finding_confidence: f32,
    entropy: f32,
    total_chars: u32,
    blake3_hash: String,
    drift_level: String,  // ADR-044
}

// ── HANDLER ───────────────────────────────────────────────────

pub async fn validate_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, StatusCode> {
    let start = Instant::now();

    // ADR-043: Rust gera verdict_id antes de qualquer processamento.
    let verdict_id = format!("VRD-{}", Ulid::new());

    // ADR-044: classificar IP e jurisdição antes do scan
    let client_ip = extract_client_ip(&headers);
    let ip_class = state.ip_classifier.classify(&client_ip);
    let ip_risk_str = ip_risk_to_str(ip_class.risk).to_string();
    let ip_jurisdiction = state.jurisdiction_mapper.classify(&client_ip).country_code.to_string();

    // ── EXECUTIVO: Rust scan + policy (sync block) ────────────
    let scan = {
        let mut gk = state.gatekeeper.lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let session_id: u128 = req.session_id
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x0000);

        let evidence = gk.scan_for_evidence(&req.input, session_id);
        let findings: Vec<_> = evidence.get_all_findings();

        // FALLBACK_POLICY é const &str compilado; from_yaml_str nunca retorna Err
        // neste path — allow pontual conforme ADR invariante boot-time.
        #[allow(clippy::unwrap_used)]
        let mut engine = PolicyEngine::from_yaml_str(DEFAULT_POLICY)
            .unwrap_or_else(|_| PolicyEngine::from_yaml_str(FALLBACK_POLICY).unwrap());

        let eval = engine.evaluate_full(&req.input, &findings);

        let policy_action = match eval.action {
            PolicyAction::Block => "BLOCK",
            PolicyAction::Redact => "REDACT",
            PolicyAction::Educate => "EDUCATE",
            PolicyAction::Log => "LOG",
            PolicyAction::Allow => "ALLOW",
        };

        let max_conf = findings.iter()
            .map(|f| f.confidence as f32 / 255.0)
            .fold(0.0_f32, f32::max);

        // ADR-044: drift calculado dentro do bloco onde evidence existe
        let drift_level = {
            let sid: u128 = req.session_id
                .as_deref().and_then(|s| s.parse().ok()).unwrap_or(0);
            if let Ok(mut tracker) = state.session_tracker.lock() {
                let result = tracker.track(sid, &evidence);
                match result.level {
                    buildtovalue_kernel::session_guard::DriftLevel::None   => "None",
                    buildtovalue_kernel::session_guard::DriftLevel::Low    => "LOW",
                    buildtovalue_kernel::session_guard::DriftLevel::Medium => "MEDIUM",
                    buildtovalue_kernel::session_guard::DriftLevel::High     => "HIGH",
                    buildtovalue_kernel::session_guard::DriftLevel::Critical => "CRITICAL",
                }.to_string()
            } else {
                "None".to_string()
            }
        };

        ScanResult {
            finding_count: evidence.finding_count as u32,
            critical_count: evidence.critical_count as u32,
            composite_risk: evidence.composite_risk,
            policy_action: policy_action.to_string(),
            hard_blocked: eval.hard_blocked,
            hard_block_term: eval.hard_block_term,
            matched_policies: eval.matched_policies,
            max_finding_confidence: max_conf,
            entropy: evidence.stats.entropy,
            total_chars: evidence.stats.total_chars,
            blake3_hash: format!("{:016x}", evidence.original_request_hash),
            drift_level,
        }
    };

    // ── JUDICIÁRIO: Python governance (async) ─────────────────
    let verdict = {
        let governance_url = std::env::var("BTV_GOVERNANCE_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());

        let gov_req = GovernanceRequest {
            finding_count: scan.finding_count,
            critical_count: scan.critical_count,
            composite_risk: scan.composite_risk,
            action: scan.policy_action.clone(),
            hard_blocked: scan.hard_blocked,
            matched_policies: scan.matched_policies.clone(),
            session_id: req.session_id.clone(),
            profile: req.profile.clone(),
            input_text: req.input.clone(),
            verdict_id: verdict_id.clone(),  // ADR-043
            max_finding_confidence: scan.max_finding_confidence,
            entropy: scan.entropy,
            total_chars: scan.total_chars,
            blake3_hash: scan.blake3_hash.clone(),
            ip_risk: ip_risk_str,
            ip_jurisdiction,
            drift_level: scan.drift_level.clone(),
        };

        match state.http_client
            .post(format!("{}/v1/decide", governance_url))
            .json(&gov_req)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<GovernanceVerdict>().await.ok()
            }
            _ => None,
        }
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // ── MERGE: Executivo + Judiciário ─────────────────────────
    // ADR-043: verdict_id gerado pelo Rust é o fallback garantido.
    // Python devolve o mesmo ID; se vier vazio (erro), usa o local.
    let (final_action, mercy_applied, final_verdict_id, rationale, signature, contestable, appeal_hours) =
        if let Some(ref v) = verdict {
            (
                v.action.clone(),
                v.mercy_applied,
                if v.verdict_id.is_empty() { verdict_id.clone() } else { v.verdict_id.clone() },
                v.rationale.clone(),
                v.signature.clone(),
                v.contestable,
                v.appeal_deadline_hours,
            )
        } else {
            // Python indisponível: ID local garante ledger + appeal funcionais.
            (
                scan.policy_action.clone(),
                false,
                verdict_id.clone(),
                String::new(),
                String::new(),
                !scan.hard_blocked,
                if scan.hard_blocked { 0 } else { 24 },
            )
        };

    // ── METRICS ───────────────────────────────────────────────
    {
        use crate::state::*;
        DECISIONS_TOTAL.with_label_values(&[&final_action]).inc();
        LATENCY_MS.observe(latency_ms);
        if mercy_applied { MERCY_APPLIED_TOTAL.inc(); }
        if scan.hard_blocked { HARD_BLOCKS_TOTAL.inc(); }
        for policy in &scan.matched_policies {
            if let Some(finding_type) = policy.split("->").next() {
                FINDINGS_TOTAL.with_label_values(&[finding_type.trim()]).inc();
            }
        }
    }

    // ── MESSAGE (user-facing) ─────────────────────────────────
    let message = if scan.hard_blocked {
        format!(
            "Mensagem bloqueada: conteudo perigoso detectado ({}). Este tipo de conteudo e proibido.",
            scan.hard_block_term.as_deref().unwrap_or("termo bloqueado")
        )
    } else if mercy_applied {
        format!(
            "Misericordia aplicada: {} -> {}. {}",
            scan.policy_action, final_action, rationale
        )
    } else {
        match final_action.as_str() {
            "BLOCK" => format!(
                "Mensagem bloqueada: {} dados sensiveis detectados ({} criticos). Risco: {:.0}%.",
                scan.finding_count, scan.critical_count, scan.composite_risk * 100.0
            ),
            "EDUCATE" => format!(
                "Alerta: {} padroes detectados. Risco: {:.0}%. Tome cuidado ao compartilhar dados sensiveis.",
                scan.finding_count, scan.composite_risk * 100.0
            ),
            "LOG" => format!(
                "Mensagem permitida com registro: {} padroes detectados.",
                scan.finding_count
            ),
            _ => "Mensagem permitida.".to_string(),
        }
    };

    // ── AUDITIVO: Ledger JSONL ────────────────────────────────
    {
        use std::io::Write;
        let session_id: u128 = req.session_id
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x0000);

        let profile_str = req.profile.as_deref().unwrap_or("default");

        let log_line = format!(
            "{{\"ts\":{},\"session\":\"{}\",\"profile\":\"{}\",\"policy_action\":\"{}\",\"final_action\":\"{}\",\"mercy\":{},\"risk\":{:.4},\"findings\":{},\"critical\":{},\"hard_blocked\":{},\"verdict_id\":\"{}\",\"latency_ms\":{:.2}}}\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            session_id,
            profile_str,
            scan.policy_action,
            final_action,
            mercy_applied,
            scan.composite_risk,
            scan.finding_count,
            scan.critical_count,
            scan.hard_blocked,
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

    // ── OUTPUT GUARD: Sanitize message before returning ───────
    let message = {
        use buildtovalue_kernel::output_guard::OutputSanitizer;
        let sanitizer = OutputSanitizer::new();
        let result = sanitizer.sanitize(&message);
        if result.masks_applied > 0 {
            log::info!(
                "OutputGuard masked {} PII in response message (audit_trail: {})",
                result.masks_applied,
                req.session_id.as_deref().unwrap_or("unknown")
            );
        }
        result.output
    };

    Ok(Json(ValidateResponse {
        finding_count: scan.finding_count,
        critical_count: scan.critical_count,
        composite_risk: scan.composite_risk,
        action: final_action,
        original_action: scan.policy_action,
        mercy_applied,
        latency_ms,
        contestable,
        appeal_deadline_hours: appeal_hours,
        message,
        hard_blocked: scan.hard_blocked,
        matched_policies: scan.matched_policies,
        verdict_id: final_verdict_id,
        signature,
        rationale,
    }))
}
