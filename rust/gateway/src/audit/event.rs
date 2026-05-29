//! `FairnessAuditEvent` — projeção humano-legível do resultado da
//! composição fairness para SIEM/DPO.
//!
//! Schema v1alpha (ADR-0088 §D2 + ADR-0090 §D3). Adição de campos via
//! `#[serde(default)]` é não-quebrante (ADR-0082). Mudança de semântica
//! de campo existente exige bump para `v1beta` ou `v1`.
//!
//! **Distinto de `LedgerEntry`** (ADR-0083) — esse é o registro forense
//! binário hash-chained no kernel. `FairnessAuditEvent` é o evento
//! humano-legível que SIEM consome.

use crate::fairness_mode::FairnessMode;
use crate::tenant_status::TenantStatus;
use serde::{Deserialize, Serialize};

/// Versão do schema. Bump apenas em mudança quebrante.
pub const SCHEMA_VERSION: &str = "v1alpha";

/// Evento durável de uma decisão fairness. Construído após
/// `apply_fairness` no handler `decide`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessAuditEvent {
    // ── Identidade ────────────────────────────────────────────────
    pub schema_version: String,

    /// UUID v7 (ordenável por tempo). Consumidores podem usar como
    /// cursor de stream.
    pub event_id: String,

    /// Epoch millis. Independente do timestamp do verdict_id para
    /// que SIEM possa indexar tempo do evento sem decodificar UUID.
    pub ts_unix_ms: u128,

    pub tenant_id: String,

    /// `verdict_id` do `decide_handler` — liga este evento à entrada
    /// correspondente do ledger forense.
    pub verdict_id: String,

    // ── Modo e estado runtime ──────────────────────────────────────
    pub fairness_mode: FairnessMode,
    pub tenant_status: TenantStatus,

    // ── Ações ──────────────────────────────────────────────────────
    /// Ação **pré-composição** (após mercy, antes de fairness).
    pub tentative_action: String,
    /// Ação que foi para o cliente (igual a `tentative_action` em
    /// modos `Disabled` ou `Shadow`).
    pub applied_action: String,
    /// Ação que a composição produziu (pode diferir de
    /// `applied_action` em `Shadow`).
    pub composed_action: String,

    // ── Flags da composição ────────────────────────────────────────
    pub composition_changed_action: bool,
    pub apply_override: bool,
    pub rawls_violation: bool,
    pub jonas_critical: bool,
    pub jonas_warning: bool,
    pub hard_block: bool,
    pub human_review_required: bool,

    // ── Erros de governança (resumo) ──────────────────────────────
    /// Lista de `error_code` (ex: "E160", "E161"). Payload completo
    /// dos erros fica em `ExplainDecision.governance_errors` na
    /// resposta HTTP — aqui apenas o resumo para indexação.
    #[serde(default)]
    pub governance_error_codes: Vec<String>,

    /// `legacy_error.extensions.error_code` quando presente.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_error_code: Option<String>,
}

impl FairnessAuditEvent {
    /// Constrói um evento com `schema_version` e `event_id` (UUID v7)
    /// preenchidos. Caller preenche os demais campos via spread.
    pub fn new(
        tenant_id: String,
        verdict_id: String,
        ts_unix_ms: u128,
        fairness_mode: FairnessMode,
        tenant_status: TenantStatus,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: uuid::Uuid::now_v7().to_string(),
            ts_unix_ms,
            tenant_id,
            verdict_id,
            fairness_mode,
            tenant_status,
            tentative_action: String::new(),
            applied_action: String::new(),
            composed_action: String::new(),
            composition_changed_action: false,
            apply_override: false,
            rawls_violation: false,
            jonas_critical: false,
            jonas_warning: false,
            hard_block: false,
            human_review_required: false,
            governance_error_codes: Vec::new(),
            legacy_error_code: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::tenant_status::DegradationCause;

    #[test]
    fn new_event_has_v7_uuid_and_schema_version() {
        let e = FairnessAuditEvent::new(
            "acme".to_string(),
            "VRD-x".to_string(),
            1_700_000_000_000,
            FairnessMode::Enforced,
            TenantStatus::Active,
        );
        assert_eq!(e.schema_version, "v1alpha");
        assert_eq!(e.event_id.len(), 36); // UUID hyphenated
        // UUID v7 começa com timestamp; o caractere de versão (posição 14)
        // deve ser '7'.
        assert_eq!(
            e.event_id.chars().nth(14),
            Some('7'),
            "esperava UUID v7, got {}",
            e.event_id
        );
    }

    #[test]
    fn event_serializes_to_jsonl_friendly_format() {
        let mut e = FairnessAuditEvent::new(
            "acme".to_string(),
            "VRD-1".to_string(),
            1_700_000_000_000,
            FairnessMode::Shadow,
            TenantStatus::Active,
        );
        e.tentative_action = "ALLOW".to_string();
        e.applied_action = "ALLOW".to_string();
        e.composed_action = "REDACT".to_string();
        e.composition_changed_action = true;
        e.rawls_violation = true;
        e.governance_error_codes = vec!["E160".to_string()];

        let json = serde_json::to_string(&e).expect("serialize");
        // Sem newlines no JSON serializado (caller adiciona \n no fim
        // para JSONL).
        assert!(!json.contains('\n'));
        assert!(json.contains("\"schema_version\":\"v1alpha\""));
        assert!(json.contains("\"fairness_mode\":\"shadow\""));
        assert!(json.contains("\"tenant_status\":{\"state\":\"active\"}"));
        assert!(json.contains("\"composed_action\":\"REDACT\""));
        assert!(json.contains("\"composition_changed_action\":true"));
        assert!(json.contains("\"governance_error_codes\":[\"E160\"]"));
    }

    #[test]
    fn event_roundtrip_serialize_deserialize() {
        let mut e = FairnessAuditEvent::new(
            "tenant-x".to_string(),
            "VRD-1".to_string(),
            42,
            FairnessMode::Enforced,
            TenantStatus::Degraded {
                cause: DegradationCause::MissingBaseline,
            },
        );
        e.applied_action = "BLOCK".to_string();
        e.hard_block = true;
        e.legacy_error_code = Some("E131".to_string());

        let json = serde_json::to_string(&e).unwrap();
        let back: FairnessAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_id, e.event_id);
        assert_eq!(back.tenant_id, e.tenant_id);
        assert!(back.hard_block);
        assert_eq!(back.legacy_error_code, Some("E131".to_string()));
        assert!(matches!(
            back.tenant_status,
            TenantStatus::Degraded { .. }
        ));
    }

    #[test]
    fn empty_governance_errors_omits_legacy_error_field() {
        let e = FairnessAuditEvent::new(
            "t".to_string(),
            "V".to_string(),
            1,
            FairnessMode::Disabled,
            TenantStatus::Active,
        );
        let json = serde_json::to_string(&e).unwrap();
        assert!(
            !json.contains("legacy_error_code"),
            "campo None deve ser omitido via skip_serializing_if; got {json}"
        );
        // Mas `governance_error_codes` vazio APARECE — comportamento
        // intencional para que consumidores não precisem distinguir
        // ausência de presença-vazia.
        assert!(json.contains("\"governance_error_codes\":[]"));
    }

    #[test]
    fn deserialize_with_missing_optional_fields_works() {
        // Garante backcompat: consumidor recebe payload v1alpha mínimo
        // sem governance_error_codes nem legacy_error_code.
        let json = r#"{
            "schema_version": "v1alpha",
            "event_id": "01927c4f-7e23-7a1b-9c4f-1f8e4c8a9d12",
            "ts_unix_ms": 1700000000000,
            "tenant_id": "acme",
            "verdict_id": "VRD-1",
            "fairness_mode": "disabled",
            "tenant_status": {"state": "active"},
            "tentative_action": "ALLOW",
            "applied_action": "ALLOW",
            "composed_action": "ALLOW",
            "composition_changed_action": false,
            "apply_override": false,
            "rawls_violation": false,
            "jonas_critical": false,
            "jonas_warning": false,
            "hard_block": false,
            "human_review_required": false
        }"#;
        let e: FairnessAuditEvent = serde_json::from_str(json).expect("parse");
        assert!(e.governance_error_codes.is_empty());
        assert!(e.legacy_error_code.is_none());
    }
}
