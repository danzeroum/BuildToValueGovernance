//! Fairness execution mode per tenant (ADR-0088 §D3).
//!
//! Shadow mode é **nível de execução**, não feature flag — distinção
//! importante:
//!
//! - Monitores Rawls/Jonas **sempre** registram, independente do modo.
//!   O buffer Jonas é populado em `Shadow` e `Enforced`; isso resolve a
//!   "ilusão estatística" do Anexo II das revisões (ADR-0087 review): em
//!   `Shadow` a evolução do PSI é monotônica crescente porque não há
//!   feedback negativo — comportamento intencional, não bug.
//! - O modo afeta apenas a **aplicação** do `FairnessDecision.action`
//!   na resposta HTTP. `Disabled` impede composição; `Shadow` roda
//!   composição mas mantém ação tentativa para o cliente; `Enforced`
//!   substitui a tentativa pelo resultado da composição.
//!
//! Default seguro: `Disabled` quando YAML ausente. Refina ADR-0088 §D3
//! para "explicit opt-in" — operadores precisam declarar modo
//! explicitamente; tenants legados sem config não são silenciosamente
//! escalados para enforce.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Modo de execução da composição fairness para um tenant.
///
/// Default: `Disabled` — explicit opt-in (ver doc do módulo).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FairnessMode {
    /// Composição não executa. Ação tentativa segue para o cliente sem
    /// passar por `compose_fairness_action`. Default quando YAML ausente.
    #[default]
    Disabled,
    /// Composição roda, evidência registrada em audit log, mas ação
    /// tentativa segue para o cliente (sem rebaixamento, sem E160/E161
    /// na resposta HTTP). Métricas em shadow são monotônicas crescentes
    /// por design.
    Shadow,
    /// Composição roda e aplica `FairnessDecision.action`. E160/E161
    /// retornados em `governance_errors`.
    Enforced,
}

impl FairnessMode {
    /// `true` se o modo permite que rationale e governance_errors do
    /// motor cheguem ao `ExplainDecision` (ainda que sem alterar action).
    pub fn populates_explain(&self) -> bool {
        matches!(self, Self::Shadow | Self::Enforced)
    }

    /// `true` se o modo aplica a ação composta na resposta HTTP.
    pub fn enforces_action(&self) -> bool {
        matches!(self, Self::Enforced)
    }
}

/// Registry per-tenant resolvido em boot a partir de
/// `policies/{tenant_id}/fairness.yaml`. Imutável após boot exceto via
/// futuro endpoint `/internal/v1/reload-policy` (out-of-scope ADR-0088).
///
/// Lê-only no hot path → `RwLock` permite reads concorrentes sem contenção.
pub struct FairnessModeRegistry {
    modes: RwLock<HashMap<String, FairnessMode>>,
}

impl Default for FairnessModeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FairnessModeRegistry {
    pub fn new() -> Self {
        Self {
            modes: RwLock::new(HashMap::new()),
        }
    }

    /// Registra ou substitui o modo para um tenant. Chamado no boot do
    /// gateway uma vez por tenant declarado em `policies/`.
    /// `#[allow(dead_code)]` mantido: chamado por lib tests e (futuro) por
    /// loader de policies/ (ADR-0089). Bin atual não invoca diretamente.
    #[allow(dead_code)]
    pub fn install(&self, tenant_id: &str, mode: FairnessMode) {
        let Ok(mut guard) = self.modes.write() else {
            return;
        };
        guard.insert(tenant_id.to_string(), mode);
    }

    /// Retorna o modo configurado para o tenant. `FairnessMode::Disabled`
    /// se o tenant não tem entry — explicit opt-in (sem fallback silencioso
    /// para Enforced).
    ///
    /// Fail-safe em lock poison: retorna `Disabled` em vez de propagar
    /// erro. Mantém o pipeline funcional sob estado degradado.
    pub fn mode_for(&self, tenant_id: &str) -> FairnessMode {
        self.modes
            .read()
            .ok()
            .and_then(|g| g.get(tenant_id).copied())
            .unwrap_or_default()
    }

    /// Remove o tenant do registry. Idempotente — `false` se não havia
    /// entry. Usado pelo `AppState::evict_tenant()` (ADR-0089 §D3).
    /// Fail-safe em lock poison.
    pub fn remove(&self, tenant_id: &str) -> bool {
        let Ok(mut guard) = self.modes.write() else {
            return false;
        };
        guard.remove(tenant_id).is_some()
    }

    /// Número de tenants com modo declarado. Útil para métricas de boot.
    /// `#[allow(dead_code)]` mantido: usado apenas em lib tests; o caller
    /// de produção será um endpoint de telemetria (ADR-0089).
    #[allow(dead_code)]
    pub fn declared_tenant_count(&self) -> usize {
        self.modes.read().map(|g| g.len()).unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        assert_eq!(FairnessMode::default(), FairnessMode::Disabled);
    }

    #[test]
    fn disabled_does_not_populate_or_enforce() {
        let m = FairnessMode::Disabled;
        assert!(!m.populates_explain());
        assert!(!m.enforces_action());
    }

    #[test]
    fn shadow_populates_but_does_not_enforce() {
        let m = FairnessMode::Shadow;
        assert!(m.populates_explain());
        assert!(!m.enforces_action());
    }

    #[test]
    fn enforced_populates_and_enforces() {
        let m = FairnessMode::Enforced;
        assert!(m.populates_explain());
        assert!(m.enforces_action());
    }

    #[test]
    fn unregistered_tenant_defaults_to_disabled() {
        let reg = FairnessModeRegistry::new();
        assert_eq!(reg.mode_for("ghost-tenant"), FairnessMode::Disabled);
    }

    #[test]
    fn registry_returns_installed_mode() {
        let reg = FairnessModeRegistry::new();
        reg.install("acme", FairnessMode::Enforced);
        reg.install("globex-shadow", FairnessMode::Shadow);
        reg.install("legacy", FairnessMode::Disabled);

        assert_eq!(reg.mode_for("acme"), FairnessMode::Enforced);
        assert_eq!(reg.mode_for("globex-shadow"), FairnessMode::Shadow);
        assert_eq!(reg.mode_for("legacy"), FairnessMode::Disabled);
        assert_eq!(reg.mode_for("unknown"), FairnessMode::Disabled);
    }

    #[test]
    fn install_replaces_existing() {
        let reg = FairnessModeRegistry::new();
        reg.install("t", FairnessMode::Shadow);
        assert_eq!(reg.mode_for("t"), FairnessMode::Shadow);
        reg.install("t", FairnessMode::Enforced);
        assert_eq!(reg.mode_for("t"), FairnessMode::Enforced);
    }

    #[test]
    fn declared_tenant_count_reflects_installs() {
        let reg = FairnessModeRegistry::new();
        assert_eq!(reg.declared_tenant_count(), 0);
        reg.install("a", FairnessMode::Shadow);
        reg.install("b", FairnessMode::Enforced);
        assert_eq!(reg.declared_tenant_count(), 2);
        // Reinstall não cria entry nova.
        reg.install("a", FairnessMode::Disabled);
        assert_eq!(reg.declared_tenant_count(), 2);
    }

    #[test]
    fn yaml_deserializes_lowercase_strings() {
        let yaml = "mode: enforced";
        #[derive(Deserialize)]
        struct Cfg {
            mode: FairnessMode,
        }
        let cfg: Cfg = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.mode, FairnessMode::Enforced);

        let cfg: Cfg = serde_yaml::from_str("mode: shadow").expect("parse");
        assert_eq!(cfg.mode, FairnessMode::Shadow);

        let cfg: Cfg = serde_yaml::from_str("mode: disabled").expect("parse");
        assert_eq!(cfg.mode, FairnessMode::Disabled);
    }
}
