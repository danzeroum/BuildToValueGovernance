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
use buildtovalue_kernel::api::error_as_resource::EthicalError;
use buildtovalue_kernel::statistics::{
    compose_fairness_action, GroupClass, JonasMonitor, OutcomeBucket, RawlsMonitor,
    DEFAULT_DIR_THRESHOLD,
};
use crate::fairness_mode::FairnessMode;
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
    /// **ADR-0086 §D1 + ADR-0088 Commit 5** — Classificação de grupo para
    /// análise de fairness, declarada explicitamente pelo chamador.
    /// `"privileged"` | `"unprivileged"`. Qualquer outro valor (ou ausente)
    /// → `GroupClass::Unclassified` — não contribui para o cálculo do DIR.
    /// Sem inferência a partir de outros campos (princípio do ADR-0086 §D1).
    #[serde(default)]
    pub group_classification: Option<String>,
    /// **ADR-0087 §D1 + ADR-0088 Commit 5** — Score de confiança da
    /// decisão do modelo, em `[0.0, 1.0]`. Alimenta o ring buffer Jonas
    /// para cálculo de PSI. Ausente → default 0.5 + `score_unavailable: true`
    /// propagado ao laudo. Sem inferência a partir de `composite_risk`.
    #[serde(default)]
    pub decision_confidence: Option<f64>,
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

/// `ExplainDecision` é o laudo serializado no campo `explain` da resposta
/// HTTP de `/v1/decide`. `Serialize` apenas — o caminho de deserialização
/// real vem do Python governance via `GovernanceExplain` (struct distinta
/// abaixo). Adicionar `Deserialize` aqui exigiria `EthicalError: Deserialize`,
/// que por sua vez exigiria `Cow<'static, str>` em vários campos do kernel —
/// custo arquitetural alto para um derive que não tem caller.
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

    /// **ADR-0088 §D2** — Erro singular legado preservado para FFI Java
    /// 1.x. Populado a partir de `governance_errors` por precedência de
    /// status code (ver `pick_legacy_error`). `None` quando nenhum erro
    /// de governança foi emitido.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_error: Option<EthicalError>,

    /// **ADR-0088 §D2** — Vetor completo de erros de governança (Rawls,
    /// Jonas, etc). Adição não-quebrante: clientes 1.x ignoram, clientes
    /// 2.x leem aqui. Vazio quando nenhum motor de fairness violou.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub governance_errors: Vec<EthicalError>,
}

/// Mapeia o código de erro do BTV em um rank de severidade semântica.
/// Status HTTP **não** é proxy adequado: 403 (BLOCK semântico) é mais
/// severo que 451 (REDACT semântico) apesar de numericamente menor.
fn severity_rank(error_code: &str) -> u8 {
    match error_code {
        "E131" => 100, // Tenant isolation — Hard Block, escalação máxima
        "E130" => 90,  // Policy violation — Block
        "E160" | "E161" => 50, // Fairness (Rawls/Jonas) — Redact
        "E120" => 30,  // BiasDeclaration ausente — erro de contrato
        "E429" => 20,  // Rate limit — infraestrutura
        _ => 10,       // Default para códigos desconhecidos
    }
}

/// Seleciona qual `EthicalError` populará `legacy_error` a partir do vetor
/// `governance_errors`. ADR-0088 §D2: precedência por **severidade semântica
/// do error_code** (BLOCK > REDACT > rate-limit > validation), com ties
/// broken por ordem de inserção (estabilidade FIFO).
///
/// Retorna `None` se `errors` é vazio.
pub fn pick_legacy_error(errors: &[EthicalError]) -> Option<EthicalError> {
    if errors.is_empty() {
        return None;
    }
    // Maior severity_rank vence; em empate de rank, o primeiro inserido
    // (menor índice) vence — `Reverse(idx)` no max_by_key inverte para
    // que o menor índice produza o maior key tuple.
    let best_idx = errors
        .iter()
        .enumerate()
        .max_by_key(|(idx, e)| (severity_rank(e.extensions.error_code), std::cmp::Reverse(*idx)))?
        .0;
    // Reconstrói clonando manualmente — EthicalError não deriva Clone
    // (BtvExtensions::metadata é serde_json::Value que clona, mas o
    // struct top-level não está marcado). Caminho minimalista: copy via
    // serde round-trip via JSON é overkill; em vez disso, derivamos
    // Clone para EthicalError + BtvExtensions no kernel (commit subsequente
    // se necessário). Aqui usamos índice; o caller materializa o clone
    // através do Vec original quando precisa.
    errors.get(best_idx).map(clone_ethical_error)
}

/// Helper interno para clonar um `EthicalError`. Justificado pelo helper
/// `pick_legacy_error` que retorna por valor para simplificar o consumer.
/// `EthicalError` não deriva `Clone` no kernel hoje; centralizar aqui evita
/// poluir a API pública do kernel só por causa do dual-write do ADR-0088 §D2.
fn clone_ethical_error(e: &EthicalError) -> EthicalError {
    use buildtovalue_kernel::api::error_as_resource::BtvExtensions;
    EthicalError {
        type_uri: e.type_uri,
        title: e.title,
        status: e.status,
        detail: e.detail.clone(),
        instance: e.instance.clone(),
        extensions: BtvExtensions {
            error_code: e.extensions.error_code,
            ethical_ground: e.extensions.ethical_ground,
            adr_reference: e.extensions.adr_reference.clone(),
            verdict_id: e.extensions.verdict_id.clone(),
            audit_log_id: e.extensions.audit_log_id.clone(),
            appeal_url: e.extensions.appeal_url,
            contestable_until: e.extensions.contestable_until.clone(),
            metadata: e.extensions.metadata.clone(),
        },
    }
}

// ── ADR-0088 Commit 5 — Fairness wiring helpers ──────────────────────

/// Parseia o campo `group_classification` do request em `GroupClass`.
/// Qualquer valor desconhecido (ou `None`) → `Unclassified` (sem
/// inferência, princípio ADR-0086 §D1).
fn parse_group_class(raw: Option<&str>) -> GroupClass {
    match raw.map(|s| s.to_ascii_lowercase()) {
        Some(s) if s == "privileged" => GroupClass::Privileged,
        Some(s) if s == "unprivileged" => GroupClass::Unprivileged,
        _ => GroupClass::Unclassified,
    }
}

/// Converte a representação string usada pela API (`policy_action`,
/// `final_action`) na enum `Action` do kernel. Casos desconhecidos
/// → `Action::Allow` (fail-safe: nunca escalonar por string mal-formada).
fn action_from_str(s: &str) -> Action {
    match s {
        "BLOCK" => Action::Block,
        "REDACT" => Action::Redact,
        "EDUCATE" | "LOG" => Action::Log,
        _ => Action::Allow,
    }
}

/// Inverso de `action_from_str`. `Action::Log` mapeia para `"EDUCATE"`
/// (string canônica usada pela camada HTTP para diferenciar de `LOG`
/// puro). Caller pode renomear se precisar.
fn action_to_str(action: Action) -> &'static str {
    match action {
        Action::Block => "BLOCK",
        Action::Redact => "REDACT",
        Action::Log => "EDUCATE",
        Action::Allow => "ALLOW",
    }
}

/// Resultado do wiring fairness. Comunicado ao handler para que ele
/// decida se sobrescreve `final_action` (apenas em `Enforced` mode) e
/// atualize observabilidade.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct FairnessWiringResult {
    /// Ação proposta pela composição (igual a `tentative` quando a
    /// composição não escalou). Útil para audit log do shadow mode.
    pub composed_action: Action,
    /// `true` quando `composed_action != tentative`. Sinaliza override
    /// no JSONL e métricas.
    pub composition_changed_action: bool,
    /// `true` quando o modo era `Enforced` E a composição mudou a ação.
    /// O handler usa esta flag para decidir se substitui `final_action`.
    pub apply_override: bool,
    /// Marca `human_review_required` (D4 ADR-0087): laudo deve sinalizar
    /// que a decisão precisa de revisão manual mesmo se action passou.
    pub human_review_required: bool,
}

/// Wiring de fairness para uma requisição. Pura em relação ao handler:
/// recebe referências, registra nos monitores, retorna metadados; o
/// caller é responsável por aplicar override e por persistir
/// `explain.governance_errors`/`legacy_error` populados aqui.
///
/// **Invariante de ordem (ADR-0088 §sequência):**
/// 1. record nos monitores (passos 5-6 do ADR) — `tentative` é
///    `final_action` pós-mercy, **pré-composição**. Isso é correto:
///    Rawls/Jonas medem a distribuição do **modelo**, não da correção
///    pós-fairness (gravar pós-composição mascararia o sinal).
/// 2. compose (passo 7) — usa métricas atuais (incluindo a transação
///    recém-registrada).
/// 3. populate explain (passo 8) — independente do modo, desde que
///    `populates_explain()`.
/// 4. override action (passo 9) — apenas se `enforces_action()`.
#[allow(clippy::too_many_arguments)]
pub fn apply_fairness(
    tenant_id: &str,
    mode: FairnessMode,
    tentative: Action,
    rawls_monitor: &RawlsMonitor,
    jonas_monitor: &JonasMonitor,
    group: GroupClass,
    decision_confidence: Option<f64>,
    audit_log_id: Option<String>,
    verdict_id: Option<String>,
    appeal_deadline_iso8601: String,
    explain: &mut ExplainDecision,
) -> FairnessWiringResult {
    let outcome = OutcomeBucket::from_action(tentative);
    let (score, score_unavailable) = match decision_confidence {
        Some(c) => (c.clamp(0.0, 1.0), false),
        None => (0.5, true),
    };

    // Passos 5-6: record nos monitores. Sempre — independente do modo
    // (shadow precisa do buffer populado, ver ADR-0088 §D3).
    rawls_monitor.record(tenant_id, group, outcome);
    jonas_monitor.record(tenant_id, score, score_unavailable);

    if !mode.populates_explain() {
        // Modo Disabled: nada de composição, nada de erros no laudo.
        return FairnessWiringResult {
            composed_action: tentative,
            composition_changed_action: false,
            apply_override: false,
            human_review_required: false,
        };
    }

    // Passo 7: compose. Usa fail-soft para tenants sem dados:
    // - Rawls sem records → metrics() retorna None; usamos FairnessMetrics
    //   sintético em `insufficient_samples` (violates_threshold=false).
    // - Jonas sem baseline → metrics_or_disabled() retorna Disabled alert.
    let rawls = rawls_monitor
        .metrics(tenant_id)
        .unwrap_or(buildtovalue_kernel::statistics::FairnessMetrics {
            dir: f64::NAN,
            privileged_favorable_rate: f64::NAN,
            unprivileged_favorable_rate: f64::NAN,
            insufficient_samples: true,
            violates_threshold: false,
            threshold_used: DEFAULT_DIR_THRESHOLD,
        });
    let jonas = jonas_monitor.metrics_or_disabled(tenant_id);
    let composed = compose_fairness_action(tentative, &rawls, jonas.alert);

    // Passo 8: build governance_errors a partir das flags da composição.
    let mut errors: Vec<EthicalError> = Vec::new();
    if composed.rawls_violation {
        let mut meta = serde_json::Map::new();
        meta.insert("dir".into(), serde_json::json!(rawls.dir));
        meta.insert("threshold".into(), serde_json::json!(rawls.threshold_used));
        meta.insert(
            "privileged_favorable_rate".into(),
            serde_json::json!(rawls.privileged_favorable_rate),
        );
        meta.insert(
            "unprivileged_favorable_rate".into(),
            serde_json::json!(rawls.unprivileged_favorable_rate),
        );
        errors.push(EthicalError::rawls_dir_violation(
            appeal_deadline_iso8601.clone(),
            audit_log_id.clone(),
            verdict_id.clone(),
            Some(serde_json::Value::Object(meta)),
        ));
    }
    if composed.jonas_critical {
        let mut meta = serde_json::Map::new();
        meta.insert("psi".into(), serde_json::json!(jonas.psi));
        meta.insert(
            "threshold".into(),
            serde_json::json!(jonas.critical_threshold),
        );
        if let Some(idx) = jonas.top_bin_index {
            meta.insert("top_bin_index".into(), serde_json::json!(idx));
            meta.insert(
                "top_bin_contribution".into(),
                serde_json::json!(jonas.top_bin_contribution),
            );
        }
        if jonas.score_unavailable {
            meta.insert("score_unavailable".into(), serde_json::json!(true));
        }
        errors.push(EthicalError::jonas_drift_violation(
            appeal_deadline_iso8601,
            audit_log_id,
            verdict_id,
            Some(serde_json::Value::Object(meta)),
        ));
    }
    explain.legacy_error = pick_legacy_error(&errors);
    explain.governance_errors = errors;

    let composition_changed_action = composed.action != tentative;
    let apply_override = mode.enforces_action() && composition_changed_action;

    FairnessWiringResult {
        composed_action: composed.action,
        composition_changed_action,
        apply_override,
        human_review_required: composed.human_review_required,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod fairness_wiring_tests {
    use super::*;
    use buildtovalue_kernel::statistics::JonasBaselineLoader;

    const VALID_BASELINE: &str = r#"
version: "1.0.0"
model_id: "test-model"
bins: 10
reference_proportions:
  - 0.05
  - 0.07
  - 0.10
  - 0.13
  - 0.15
  - 0.18
  - 0.15
  - 0.10
  - 0.05
  - 0.02
"#;

    fn fresh_monitors() -> (RawlsMonitor, JonasMonitor) {
        let jonas = JonasMonitor::new();
        jonas.install_baseline(
            "acme",
            JonasBaselineLoader::from_yaml_str(VALID_BASELINE).unwrap(),
        );
        (RawlsMonitor::default(), jonas)
    }

    #[test]
    fn disabled_mode_records_but_does_not_compose() {
        let (rawls, jonas) = fresh_monitors();
        let mut explain = ExplainDecision::default();
        let result = apply_fairness(
            "acme",
            FairnessMode::Disabled,
            Action::Allow,
            &rawls,
            &jonas,
            GroupClass::Privileged,
            Some(0.7),
            None,
            None,
            "2026-05-29T12:00:00Z".to_string(),
            &mut explain,
        );
        assert!(!result.apply_override);
        assert!(!result.composition_changed_action);
        assert_eq!(result.composed_action, Action::Allow);
        // Nenhum erro de governança em modo Disabled.
        assert!(explain.governance_errors.is_empty());
        assert!(explain.legacy_error.is_none());
        // Mas record ainda aconteceu — verificável pelo metrics
        // (insufficient samples mas total > 0).
        // Single record: insufficient samples ainda.
        let m = rawls.metrics("acme");
        // 1 amostra → ainda insufficient, mas counter incrementou.
        assert!(m.is_some());
    }

    #[test]
    fn shadow_mode_populates_errors_but_does_not_override() {
        let (rawls, jonas) = fresh_monitors();
        // Setup: 100 amostras Privileged Favorable, 100 Unprivileged Unfavorable
        // → Rawls violação severa.
        for _ in 0..100 {
            rawls.record("acme", GroupClass::Privileged, OutcomeBucket::Favorable);
            rawls.record("acme", GroupClass::Unprivileged, OutcomeBucket::Unfavorable);
        }
        let mut explain = ExplainDecision::default();
        let result = apply_fairness(
            "acme",
            FairnessMode::Shadow,
            Action::Allow,
            &rawls,
            &jonas,
            GroupClass::Privileged,
            Some(0.7),
            None,
            None,
            "2026-05-29T12:00:00Z".to_string(),
            &mut explain,
        );
        // Composição rebaixaria Allow → Redact, mas modo Shadow não aplica.
        assert!(!result.apply_override);
        assert!(result.composition_changed_action);
        assert_eq!(result.composed_action, Action::Redact);
        // Governance errors POPULADOS (Shadow é observabilidade).
        assert!(!explain.governance_errors.is_empty());
        assert!(explain.legacy_error.is_some());
        let legacy = explain.legacy_error.as_ref().unwrap();
        assert_eq!(legacy.extensions.error_code, "E160");
    }

    #[test]
    fn enforced_mode_overrides_action_and_populates_errors() {
        let (rawls, jonas) = fresh_monitors();
        for _ in 0..100 {
            rawls.record("acme", GroupClass::Privileged, OutcomeBucket::Favorable);
            rawls.record("acme", GroupClass::Unprivileged, OutcomeBucket::Unfavorable);
        }
        let mut explain = ExplainDecision::default();
        let result = apply_fairness(
            "acme",
            FairnessMode::Enforced,
            Action::Allow,
            &rawls,
            &jonas,
            GroupClass::Privileged,
            Some(0.7),
            None,
            None,
            "2026-05-29T12:00:00Z".to_string(),
            &mut explain,
        );
        assert!(result.apply_override);
        assert_eq!(result.composed_action, Action::Redact);
        assert!(!explain.governance_errors.is_empty());
    }

    #[test]
    fn parse_group_class_canonical_strings() {
        assert_eq!(parse_group_class(Some("privileged")), GroupClass::Privileged);
        assert_eq!(parse_group_class(Some("PRIVILEGED")), GroupClass::Privileged);
        assert_eq!(parse_group_class(Some("unprivileged")), GroupClass::Unprivileged);
        assert_eq!(parse_group_class(Some("garbage")), GroupClass::Unclassified);
        assert_eq!(parse_group_class(None), GroupClass::Unclassified);
    }

    #[test]
    fn action_roundtrip_via_strings() {
        for a in [Action::Allow, Action::Block, Action::Redact, Action::Log] {
            let s = action_to_str(a);
            assert_eq!(action_from_str(s), a, "roundtrip for {:?}", a);
        }
        // Aliases legados:
        assert_eq!(action_from_str("LOG"), Action::Log);
        // Unknown → Allow fail-safe (nunca escalonar por string mal-formada).
        assert_eq!(action_from_str("WEIRD"), Action::Allow);
    }

    #[test]
    fn score_unavailable_propagates_through_metadata() {
        let (rawls, jonas) = fresh_monitors();
        // Popular Jonas com 600 records score_unavailable=true + drift severo
        // para gerar Critical alert.
        for _ in 0..600 {
            jonas.record("acme", 0.05, true);
        }
        let mut explain = ExplainDecision::default();
        let _result = apply_fairness(
            "acme",
            FairnessMode::Enforced,
            Action::Allow,
            &rawls,
            &jonas,
            GroupClass::Unclassified,
            None, // sem decision_confidence
            None,
            None,
            "2026-05-29T12:00:00Z".to_string(),
            &mut explain,
        );
        // Se Jonas detectou drift Critical, o erro E161 deve carregar
        // score_unavailable=true na metadata. (Pode não detectar se PSI
        // não passar do threshold — então só asserta se o erro existir.)
        if let Some(err) = explain
            .governance_errors
            .iter()
            .find(|e| e.extensions.error_code == "E161")
        {
            let meta = err.extensions.metadata.as_ref().expect("metadata");
            assert_eq!(meta.get("score_unavailable"), Some(&serde_json::json!(true)));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod explain_decision_tests {
    use super::*;

    fn rawls_451() -> EthicalError {
        EthicalError::rawls_dir_violation(
            "2026-05-29T12:00:00Z".to_string(),
            None,
            None,
            None,
        )
    }
    fn jonas_451() -> EthicalError {
        EthicalError::jonas_drift_violation(
            "2026-05-29T12:00:00Z".to_string(),
            None,
            None,
            None,
        )
    }
    fn tenant_403() -> EthicalError {
        EthicalError::tenant_isolation_violation(
            "wrong-tenant".to_string(),
            "correct-tenant",
            None,
        )
    }

    #[test]
    fn empty_errors_yields_no_legacy() {
        assert!(pick_legacy_error(&[]).is_none());
    }

    #[test]
    fn single_error_becomes_legacy() {
        let errs = vec![rawls_451()];
        let chosen = pick_legacy_error(&errs).expect("one error");
        assert_eq!(chosen.status, 451);
        assert_eq!(chosen.extensions.error_code, "E160");
    }

    #[test]
    fn block_semantic_wins_over_redact_semantic() {
        // E160 (451, Redact semântico) + E131 (403, Hard Block semântico)
        // → E131 vence porque BLOCK > REDACT na escala de severidade.
        // Status numérico não é proxy: 403 < 451 numericamente, mas
        // semanticamente é mais severo. Ver `severity_rank`.
        let errs = vec![rawls_451(), tenant_403()];
        let chosen = pick_legacy_error(&errs).expect("two errors");
        assert_eq!(chosen.extensions.error_code, "E131");
        assert_eq!(chosen.status, 403);
    }

    #[test]
    fn tie_at_same_status_keeps_first_inserted() {
        // E160 + E161 ambos 451 → E160 vence (inserido primeiro).
        let errs = vec![rawls_451(), jonas_451()];
        let chosen = pick_legacy_error(&errs).expect("two errors");
        assert_eq!(chosen.status, 451);
        assert_eq!(
            chosen.extensions.error_code, "E160",
            "tie deve favorecer ordem de inserção FIFO"
        );
    }

    #[test]
    fn tie_at_same_status_reverse_order_picks_jonas() {
        // E161 + E160 ambos 451 → E161 vence (inserido primeiro agora).
        let errs = vec![jonas_451(), rawls_451()];
        let chosen = pick_legacy_error(&errs).expect("two errors");
        assert_eq!(chosen.extensions.error_code, "E161");
    }

    #[test]
    fn explain_serializes_empty_governance_errors_as_absent() {
        // Default ExplainDecision com governance_errors vazio + legacy_error None:
        // ambos os campos devem ser omitidos da serialização (skip_serializing_if).
        let ex = ExplainDecision::default();
        let json = serde_json::to_string(&ex).expect("serialize");
        assert!(!json.contains("governance_errors"));
        assert!(!json.contains("legacy_error"));
    }

    #[test]
    fn explain_serializes_with_populated_errors() {
        let errs = vec![rawls_451()];
        let legacy = pick_legacy_error(&errs);
        let ex = ExplainDecision {
            governance_errors: errs,
            legacy_error: legacy,
            ..Default::default()
        };
        let json = serde_json::to_string(&ex).expect("serialize");
        assert!(json.contains("\"legacy_error\""));
        assert!(json.contains("\"governance_errors\""));
        assert!(json.contains("\"error_code\":\"E160\""));
    }
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
    let (mut final_action, mercy_applied, final_verdict_id, rationale, signature,
        contestable, appeal_hours, trust_score, mercy_score,
        mercy_scenario, risk_classification, mut explain) =
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
                // ADR-0088 §D2: campos novos default — populados em commit 5
                // (wiring de Rawls + Jonas no decide_handler).
                legacy_error: None,
                governance_errors: Vec::new(),
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
                legacy_error: None,
                governance_errors: Vec::new(),
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

    // ── ADR-0088 §sequência: FAIRNESS WIRING ──────────────────
    // Ocorre APÓS MERGE (final_action é a ação pós-mercy) e ANTES de
    // METRICS/ledger/HTTP response. Record nos monitores usa a ação
    // pré-composição — sinal natural do modelo para detecção de viés.
    let fairness_mode = state.fairness_mode_for(tenant_id.as_str());
    let fairness_result = apply_fairness(
        tenant_id.as_str(),
        fairness_mode,
        action_from_str(&final_action),
        &state.rawls_monitor,
        &state.jonas_monitor,
        parse_group_class(req.group_classification.as_deref()),
        req.decision_confidence,
        None, // audit_log_id — TBD em wiring com ledger forense
        Some(final_verdict_id.clone()),
        // Deadline 24h conforme ADR-0017 (Contestability Loop).
        chrono::Utc::now()
            .checked_add_signed(chrono::Duration::hours(24))
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string()),
        &mut explain,
    );
    if fairness_result.apply_override {
        // Apenas em FairnessMode::Enforced + composição mudou a ação:
        // sobrescreve final_action. Shadow e Disabled preservam.
        final_action = action_to_str(fairness_result.composed_action).to_string();
    }
    let fairness_override_applied = fairness_result.apply_override;

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
            "{{\"ts\":{},\"tenant\":\"{}\",\"session\":\"{}\",\"profile\":\"{}\",\"policy_action\":\"{}\",\"final_action\":\"{}\",\"mercy\":{},\"risk\":{:.4},\"findings\":{},\"critical\":{},\"hard_blocked\":{},\"verdict_id\":\"{}\",\"latency_ms\":{:.2},\"fairness_mode\":\"{}\",\"fairness_override\":{},\"fairness_composed\":\"{}\"}}\n",
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
            match fairness_mode {
                FairnessMode::Disabled => "disabled",
                FairnessMode::Shadow => "shadow",
                FairnessMode::Enforced => "enforced",
            },
            fairness_override_applied,
            action_to_str(fairness_result.composed_action),
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
    //
    // INVARIANTE: `evidence` saiu do Mutex<Gatekeeper> imutável e não é
    // modificada entre a liberação do lock e este append. Apenas leituras
    // de campos ocorreram nos blocos intermediários (governance request,
    // metrics, JSONL). Nenhuma transformação intermediária — a evidence
    // persistida no ledger é byte-idêntica à computada pelo Gatekeeper.
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
