//! Tenant runtime status (ADR-0089 §D1).
//!
//! NOTE on `dead_code`: o módulo é introduzido neste Commit 3, mas o
//! consumidor de produção é o decide_handler (Commit 5 do ADR-0089) +
//! AppState orquestrador (Commit 6). Lib tests aqui exercitam o registry
//! completo. `#![allow(dead_code)]` evita falha no `RUSTFLAGS="-D warnings"`
//! da Workspace Integrity até o wiring final. Remover após Commit 5.
#![allow(dead_code)]

//!
//! **Ortogonal a `FairnessMode`:**
//!
//! - `FairnessMode` = config declarada (Disabled/Shadow/Enforced), imutável
//!   durante execução, lida de `policies/{tenant}/fairness.yaml` no boot.
//! - `TenantStatus` = estado runtime (Initializing/Active/Degraded), mutável
//!   pelo boot step + endpoints `/internal/v1/reload-policy` e `/evict`.
//!
//! O `decide_handler` consulta **ambos** antes de despachar:
//!
//! ```text
//! match (status, mode) {
//!     (Degraded(_),    _)        => REDACT + governance_errors[fairness_loading]
//!     (Initializing,   _)        => REDACT + fairness_loading=true
//!     (Active, FairnessMode::Disabled) => skip pipeline fairness
//!     (Active, _)                => apply_fairness normal
//! }
//! ```
//!
//! **Default `TenantStatus::Active` para tenants sem entry no registry.**
//!
//! Por que `Active` (não `Initializing`): o boot step (ADR-0089 §D1) carrega
//! todos os tenants declarados em `policies/` ANTES de `axum::serve`. Um
//! tenant sem entry é um tenant que NUNCA foi configurado para fairness —
//! operação normal, combinado com `FairnessMode::Disabled` (também default)
//! resulta em skip de pipeline = zero overhead. Default `Initializing`
//! exigiria que o boot marcasse explicitamente todos os tenants, incluindo
//! os não configurados — sobrecarga sem ganho.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Causa de degradação. Mensagens String capturam contexto do erro
/// (BaselineError display, mensagem de I/O, etc) para o operador.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DegradationCause {
    /// `policies/{tenant}/drift_baseline.yaml` ausente.
    MissingBaseline,
    /// YAML do baseline malformado ou inválido pelo schema.
    InvalidBaseline { reason: String },
    /// `policies/{tenant}/fairness.yaml` malformado.
    InvalidFairnessYaml { reason: String },
    /// **Reservado para E162** (ADR-0087 Fase 2 — verificação ativa SHA-256).
    /// Não emitido nesta fase; documentado para que operadores não confundam
    /// com `InvalidBaseline`.
    BaselineHashMismatch { expected: String, actual: String },
}

impl std::fmt::Display for DegradationCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBaseline => write!(f, "drift_baseline.yaml ausente"),
            Self::InvalidBaseline { reason } => write!(f, "baseline inválido: {reason}"),
            Self::InvalidFairnessYaml { reason } => {
                write!(f, "fairness.yaml inválido: {reason}")
            }
            Self::BaselineHashMismatch { expected, actual } => write!(
                f,
                "baseline hash mismatch (expected {expected}, got {actual})"
            ),
        }
    }
}

/// Estado runtime de um tenant para o pipeline fairness.
///
/// Default = `Active` (semântica documentada no header do módulo:
/// tenant sem entry no registry assume operação normal, pois o boot step
/// carrega todos os declarados antes de aceitar tráfego).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TenantStatus {
    /// Boot step ainda processando este tenant. Fail-soft no handler:
    /// REDACT com `governance_errors[fairness_loading]`. Janela típica:
    /// milissegundos a poucos segundos.
    Initializing,
    /// Baseline + fairness.yaml carregados com sucesso (ou tenant sem
    /// config — comportamento normal sem pipeline fairness).
    #[default]
    Active,
    /// Falha de carregamento; outros tenants não afetados. Handler
    /// rebaixa para REDACT e propaga a causa em `governance_errors`.
    Degraded { cause: DegradationCause },
}

impl TenantStatus {
    /// `true` se o handler deve aplicar fail-soft (rebaixar a REDACT e
    /// emitir flag/causa em `governance_errors`).
    pub fn is_failsoft(&self) -> bool {
        matches!(self, Self::Initializing | Self::Degraded { .. })
    }

    /// Retorna a causa de degradação se aplicável.
    pub fn degradation_cause(&self) -> Option<&DegradationCause> {
        match self {
            Self::Degraded { cause } => Some(cause),
            _ => None,
        }
    }
}

/// Registry de status por tenant. Atualizado pelo boot step
/// (`policy_loader.rs`, Commit 4) e endpoints `/internal/v1/*`
/// (Commit 5).
///
/// Sem entry → `Active` default. Veja doc do módulo.
pub struct TenantStatusRegistry {
    statuses: RwLock<HashMap<String, TenantStatus>>,
}

impl Default for TenantStatusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantStatusRegistry {
    pub fn new() -> Self {
        Self {
            statuses: RwLock::new(HashMap::new()),
        }
    }

    /// Retorna o status atual. `Active` se o tenant não tem entry.
    /// Fail-safe em lock poison → `Active` (mantém pipeline funcional
    /// sob estado degradado de concorrência).
    pub fn status_for(&self, tenant_id: &str) -> TenantStatus {
        self.statuses
            .read()
            .ok()
            .and_then(|g| g.get(tenant_id).cloned())
            .unwrap_or_default()
    }

    /// Define o status para um tenant. Substitui qualquer entry existente.
    pub fn set(&self, tenant_id: &str, status: TenantStatus) {
        let Ok(mut guard) = self.statuses.write() else {
            return;
        };
        guard.insert(tenant_id.to_string(), status);
    }

    pub fn mark_initializing(&self, tenant_id: &str) {
        self.set(tenant_id, TenantStatus::Initializing);
    }

    pub fn mark_active(&self, tenant_id: &str) {
        self.set(tenant_id, TenantStatus::Active);
    }

    pub fn mark_degraded(&self, tenant_id: &str, cause: DegradationCause) {
        self.set(tenant_id, TenantStatus::Degraded { cause });
    }

    /// Remove a entry. Idempotente — `false` se não havia entry.
    /// Usado pelo `AppState::evict_tenant()` (Commit 6).
    pub fn remove(&self, tenant_id: &str) -> bool {
        let Ok(mut guard) = self.statuses.write() else {
            return false;
        };
        guard.remove(tenant_id).is_some()
    }

    /// Número de tenants com entry explícita (não conta defaults).
    pub fn tracked_tenant_count(&self) -> usize {
        self.statuses.read().map(|g| g.len()).unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_status_is_active() {
        // Decisão ADR-0089 D1: tenant sem entry → Active (não Initializing).
        // Boot step carrega antes de aceitar tráfego; sem entry significa
        // tenant nunca declarado em policies/.
        assert_eq!(TenantStatus::default(), TenantStatus::Active);
    }

    #[test]
    fn unknown_tenant_in_registry_returns_active() {
        let reg = TenantStatusRegistry::new();
        assert_eq!(reg.status_for("ghost"), TenantStatus::Active);
        assert_eq!(reg.tracked_tenant_count(), 0);
    }

    #[test]
    fn explicit_active_set_is_tracked() {
        let reg = TenantStatusRegistry::new();
        reg.mark_active("acme");
        assert_eq!(reg.status_for("acme"), TenantStatus::Active);
        assert_eq!(reg.tracked_tenant_count(), 1);
        // Mesmo resultado de status que default, mas entry existe.
    }

    #[test]
    fn initializing_state_is_failsoft() {
        let reg = TenantStatusRegistry::new();
        reg.mark_initializing("acme");
        let s = reg.status_for("acme");
        assert_eq!(s, TenantStatus::Initializing);
        assert!(s.is_failsoft());
        assert!(s.degradation_cause().is_none());
    }

    #[test]
    fn degraded_carries_cause_and_is_failsoft() {
        let reg = TenantStatusRegistry::new();
        reg.mark_degraded(
            "acme",
            DegradationCause::InvalidBaseline {
                reason: "bin count mismatch".to_string(),
            },
        );
        let s = reg.status_for("acme");
        assert!(s.is_failsoft());
        let cause = s.degradation_cause().expect("cause");
        assert!(matches!(cause, DegradationCause::InvalidBaseline { .. }));
    }

    #[test]
    fn set_replaces_existing_status() {
        let reg = TenantStatusRegistry::new();
        reg.mark_initializing("acme");
        assert_eq!(reg.status_for("acme"), TenantStatus::Initializing);
        reg.mark_active("acme");
        assert_eq!(reg.status_for("acme"), TenantStatus::Active);
        reg.mark_degraded("acme", DegradationCause::MissingBaseline);
        assert!(matches!(reg.status_for("acme"), TenantStatus::Degraded { .. }));
        assert_eq!(reg.tracked_tenant_count(), 1, "reinstall não cria entry nova");
    }

    #[test]
    fn remove_is_idempotent() {
        let reg = TenantStatusRegistry::new();
        assert!(!reg.remove("ghost"));
        reg.mark_initializing("acme");
        assert!(reg.remove("acme"));
        assert!(!reg.remove("acme"));
        // Após remoção, status volta ao default Active.
        assert_eq!(reg.status_for("acme"), TenantStatus::Active);
    }

    #[test]
    fn tenants_are_isolated() {
        let reg = TenantStatusRegistry::new();
        reg.mark_initializing("a");
        reg.mark_degraded("b", DegradationCause::MissingBaseline);
        assert_eq!(reg.status_for("a"), TenantStatus::Initializing);
        assert!(matches!(reg.status_for("b"), TenantStatus::Degraded { .. }));
        assert_eq!(reg.status_for("c"), TenantStatus::Active); // default
    }

    #[test]
    fn degradation_cause_display_messages() {
        assert!(DegradationCause::MissingBaseline
            .to_string()
            .contains("ausente"));
        assert!(DegradationCause::InvalidBaseline {
            reason: "x".to_string(),
        }
        .to_string()
        .contains("baseline inválido: x"));
        assert!(DegradationCause::BaselineHashMismatch {
            expected: "abc".to_string(),
            actual: "def".to_string(),
        }
        .to_string()
        .contains("expected abc"));
    }

    #[test]
    fn status_serializes_with_tag() {
        // Garante schema HTTP estável para endpoints /internal/v1/.
        let s = TenantStatus::Active;
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"state\":\"active\""));

        let s = TenantStatus::Degraded {
            cause: DegradationCause::MissingBaseline,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"state\":\"degraded\""));
        assert!(json.contains("\"type\":\"missing_baseline\""));
    }

    #[test]
    fn handler_dispatch_table_via_match() {
        // Sentinela: documenta a tabela de despacho do decide_handler
        // (Commit 5) como teste vivo. Não exercita o handler em si,
        // mas confirma que TenantStatus + FairnessMode formam um pattern
        // match exaustivo viável.
        use crate::fairness_mode::FairnessMode;

        fn dispatch(status: &TenantStatus, mode: FairnessMode) -> &'static str {
            match (status, mode) {
                (TenantStatus::Degraded { .. }, _) => "failsoft_redact_with_cause",
                (TenantStatus::Initializing, _) => "failsoft_redact_loading",
                (TenantStatus::Active, FairnessMode::Disabled) => "skip_pipeline",
                (TenantStatus::Active, FairnessMode::Shadow) => "apply_fairness_shadow",
                (TenantStatus::Active, FairnessMode::Enforced) => "apply_fairness_enforced",
            }
        }

        assert_eq!(
            dispatch(&TenantStatus::Active, FairnessMode::Disabled),
            "skip_pipeline"
        );
        assert_eq!(
            dispatch(&TenantStatus::Active, FairnessMode::Enforced),
            "apply_fairness_enforced"
        );
        assert_eq!(
            dispatch(&TenantStatus::Initializing, FairnessMode::Enforced),
            "failsoft_redact_loading"
        );
        assert_eq!(
            dispatch(
                &TenantStatus::Degraded {
                    cause: DegradationCause::MissingBaseline
                },
                FairnessMode::Enforced
            ),
            "failsoft_redact_with_cause"
        );
    }
}
