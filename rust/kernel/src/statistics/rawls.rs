//! Rawls Disparate Impact Monitor (ADR-0086).
//!
//! Calcula o Disparate Impact Ratio (DIR):
//!
//! ```text
//! DIR = P(favorável | Unprivileged) / P(favorável | Privileged)
//! ```
//!
//! Convenção legal (EEOC 80% Rule): `DIR < 0.80` caracteriza disparate
//! impact. Reusada por LGPD Art. 20 e EU AI Act Art. 14.
//!
//! Storage: contadores agregados em memória por tenant (ver ADR-0086 §D2).
//! Não há SQLite onde indexar — o ledger é binário (`LedgerEntry` 384B).
//! Snapshots periódicos para persistência ficam em ADR futuro.
//!
//! Invariantes:
//! - `GroupClass::Unclassified` nunca entra no DIR.
//! - Amostra insuficiente (`< RAWLS_MIN_SAMPLES_PER_GROUP`) retorna
//!   `dir = f64::NAN` com flag `insufficient_samples` — evita falso
//!   positivo por sample size pequeno.
//! - `record()` é O(1); `compute_dir()` é O(1) sobre contadores agregados.

use crate::core::types::Action;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Threshold de violação DIR (regra dos 4/5).
pub const DEFAULT_DIR_THRESHOLD: f64 = 0.80;

/// Janela amostral por tenant (eventos retidos para cálculo).
pub const RAWLS_WINDOW_SIZE: usize = 10_000;

/// Mínimo de amostras por grupo para considerar DIR estatisticamente válido.
pub const RAWLS_MIN_SAMPLES_PER_GROUP: u64 = 30;

/// Classificação de grupo para análise de fairness. Declarada pelo
/// chamador via `AttestedContext.group_classification` — nunca inferida
/// de outros campos (ver ADR-0086 §D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GroupClass {
    /// Referência da política do tenant (grupo dominante).
    Privileged,
    /// Grupo monitorado para fairness (vulnerável/minoritário).
    Unprivileged,
    /// Não classificado — fora da janela amostral, NÃO entra no DIR.
    Unclassified,
}

/// Bucket de outcome para Rawls. Mapeamento de `Action` segue ADR-0086 §D3:
/// favorável = `Allow ∪ Redact ∪ Log` (qualquer decisão que não seja Block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutcomeBucket {
    Favorable,
    Unfavorable,
}

impl OutcomeBucket {
    /// Convenção ADR-0086 §D3: Block → Unfavorable; demais → Favorable.
    pub fn from_action(action: Action) -> Self {
        match action {
            Action::Block => Self::Unfavorable,
            Action::Allow | Action::Redact | Action::Log => Self::Favorable,
        }
    }
}

/// Contadores agregados por tenant. Atualizados em O(1) a cada decisão.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawlsCounters {
    pub privileged_favorable: u64,
    pub privileged_unfavorable: u64,
    pub unprivileged_favorable: u64,
    pub unprivileged_unfavorable: u64,
    /// Total de eventos observados (inclui Unclassified que não conta no DIR).
    pub total_events: u64,
}

impl RawlsCounters {
    pub fn privileged_total(&self) -> u64 {
        self.privileged_favorable + self.privileged_unfavorable
    }

    pub fn unprivileged_total(&self) -> u64 {
        self.unprivileged_favorable + self.unprivileged_unfavorable
    }

    /// Incrementa contador apropriado. `Unclassified` afeta apenas `total_events`.
    pub fn record(&mut self, group: GroupClass, outcome: OutcomeBucket) {
        self.total_events = self.total_events.saturating_add(1);
        match (group, outcome) {
            (GroupClass::Privileged, OutcomeBucket::Favorable) => {
                self.privileged_favorable = self.privileged_favorable.saturating_add(1);
            }
            (GroupClass::Privileged, OutcomeBucket::Unfavorable) => {
                self.privileged_unfavorable = self.privileged_unfavorable.saturating_add(1);
            }
            (GroupClass::Unprivileged, OutcomeBucket::Favorable) => {
                self.unprivileged_favorable = self.unprivileged_favorable.saturating_add(1);
            }
            (GroupClass::Unprivileged, OutcomeBucket::Unfavorable) => {
                self.unprivileged_unfavorable = self.unprivileged_unfavorable.saturating_add(1);
            }
            (GroupClass::Unclassified, _) => {}
        }
    }
}

/// Métrica Rawls computada para um tenant em ponto-no-tempo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessMetrics {
    /// Disparate Impact Ratio. `f64::NAN` se amostra insuficiente.
    pub dir: f64,
    /// Taxa favorável do grupo Privileged. `f64::NAN` se < MIN_SAMPLES.
    pub privileged_favorable_rate: f64,
    /// Taxa favorável do grupo Unprivileged. `f64::NAN` se < MIN_SAMPLES.
    pub unprivileged_favorable_rate: f64,
    /// `true` se algum grupo tem `< RAWLS_MIN_SAMPLES_PER_GROUP` amostras.
    pub insufficient_samples: bool,
    /// `true` se `dir < threshold` (e amostra suficiente).
    pub violates_threshold: bool,
    /// Threshold aplicado neste cálculo (permite override futuro).
    pub threshold_used: f64,
}

impl FairnessMetrics {
    /// Constrói `FairnessMetrics` em estado "amostra insuficiente".
    fn insufficient(threshold: f64) -> Self {
        Self {
            dir: f64::NAN,
            privileged_favorable_rate: f64::NAN,
            unprivileged_favorable_rate: f64::NAN,
            insufficient_samples: true,
            violates_threshold: false,
            threshold_used: threshold,
        }
    }
}

/// Calcula DIR sobre contadores agregados. O(1).
///
/// Retorna `insufficient_samples = true` (com `dir = NaN`) quando qualquer
/// grupo tem menos que `RAWLS_MIN_SAMPLES_PER_GROUP` observações.
pub fn compute_dir(counters: &RawlsCounters, threshold: f64) -> FairnessMetrics {
    let priv_total = counters.privileged_total();
    let unpriv_total = counters.unprivileged_total();

    if priv_total < RAWLS_MIN_SAMPLES_PER_GROUP
        || unpriv_total < RAWLS_MIN_SAMPLES_PER_GROUP
    {
        return FairnessMetrics::insufficient(threshold);
    }

    let priv_rate = counters.privileged_favorable as f64 / priv_total as f64;
    let unpriv_rate = counters.unprivileged_favorable as f64 / unpriv_total as f64;

    // Privileged com taxa favorável zero (improvável mas possível): DIR
    // tecnicamente indefinido. Convenção: considerar paridade (DIR = 1.0)
    // para evitar divisão por zero — não há disparate impact se nenhum
    // grupo está sendo beneficiado.
    let dir = if priv_rate == 0.0 {
        1.0
    } else {
        unpriv_rate / priv_rate
    };

    FairnessMetrics {
        dir,
        privileged_favorable_rate: priv_rate,
        unprivileged_favorable_rate: unpriv_rate,
        insufficient_samples: false,
        violates_threshold: dir < threshold,
        threshold_used: threshold,
    }
}

/// Monitor global de fairness por tenant.
///
/// `record()` é chamado pelo Gatekeeper após cada decisão; `metrics()`
/// é chamado por `EthicsValidator` ou por endpoint de telemetria.
pub struct RawlsMonitor {
    counters: RwLock<HashMap<String, RawlsCounters>>,
    threshold: f64,
}

impl Default for RawlsMonitor {
    fn default() -> Self {
        Self::new(DEFAULT_DIR_THRESHOLD)
    }
}

impl RawlsMonitor {
    pub fn new(threshold: f64) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            threshold,
        }
    }

    /// Registra uma decisão. Fail-safe: lock poison → noop (a decisão
    /// já foi tomada; perder uma amostra não justifica derrubar o request).
    pub fn record(&self, tenant_id: &str, group: GroupClass, outcome: OutcomeBucket) {
        let Ok(mut guard) = self.counters.write() else {
            return;
        };
        let entry = guard.entry(tenant_id.to_string()).or_default();
        entry.record(group, outcome);
    }

    /// Calcula DIR para um tenant. Retorna `None` se o tenant nunca foi
    /// registrado, `Some(FairnessMetrics)` caso contrário (pode estar em
    /// estado `insufficient_samples`).
    pub fn metrics(&self, tenant_id: &str) -> Option<FairnessMetrics> {
        let guard = self.counters.read().ok()?;
        let counters = guard.get(tenant_id)?;
        Some(compute_dir(counters, self.threshold))
    }

    /// Snapshot dos contadores para um tenant. Usado por testes e
    /// (eventualmente) por persistência ADR futuro.
    pub fn snapshot(&self, tenant_id: &str) -> Option<RawlsCounters> {
        let guard = self.counters.read().ok()?;
        guard.get(tenant_id).cloned()
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Remove o estado do tenant. Idempotente. Fail-safe em lock poison
    /// (retorna false). Ver ADR-0089 §D3.
    pub fn remove_tenant(&self, tenant_id: &str) -> bool {
        let Ok(mut guard) = self.counters.write() else {
            return false;
        };
        guard.remove(tenant_id).is_some()
    }
}

impl crate::statistics::reloadable::ReloadableGuardrail for RawlsMonitor {
    /// Rawls não tem baseline YAML — threshold é compile-time
    /// (`DEFAULT_DIR_THRESHOLD`). Retorna `NotApplicable`; gateway trata
    /// como noop OK.
    fn reload_baseline(
        &self,
        _tenant_id: &str,
        _yaml_content: &str,
    ) -> Result<(), crate::statistics::reloadable::ReloadError> {
        Err(crate::statistics::reloadable::ReloadError::NotApplicable)
    }

    fn remove_tenant(&self, tenant_id: &str) -> bool {
        RawlsMonitor::remove_tenant(self, tenant_id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn record_n(
        counters: &mut RawlsCounters,
        group: GroupClass,
        outcome: OutcomeBucket,
        n: u64,
    ) {
        for _ in 0..n {
            counters.record(group, outcome);
        }
    }

    #[test]
    fn favorable_action_mapping_matches_adr_d3() {
        assert_eq!(OutcomeBucket::from_action(Action::Allow), OutcomeBucket::Favorable);
        assert_eq!(OutcomeBucket::from_action(Action::Redact), OutcomeBucket::Favorable);
        assert_eq!(OutcomeBucket::from_action(Action::Log), OutcomeBucket::Favorable);
        assert_eq!(OutcomeBucket::from_action(Action::Block), OutcomeBucket::Unfavorable);
    }

    #[test]
    fn insufficient_samples_returns_nan_dir() {
        let mut c = RawlsCounters::default();
        // Apenas 10 amostras em cada grupo — abaixo do mínimo de 30.
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Favorable, 10);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Favorable, 10);

        let m = compute_dir(&c, DEFAULT_DIR_THRESHOLD);
        assert!(m.insufficient_samples);
        assert!(m.dir.is_nan());
        assert!(!m.violates_threshold);
    }

    #[test]
    fn parity_yields_dir_one_no_violation() {
        let mut c = RawlsCounters::default();
        // 100 em cada grupo, 80% favoráveis — DIR = 1.0.
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Favorable, 80);
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Unfavorable, 20);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Favorable, 80);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Unfavorable, 20);

        let m = compute_dir(&c, DEFAULT_DIR_THRESHOLD);
        assert!(!m.insufficient_samples);
        assert!((m.dir - 1.0).abs() < 1e-9);
        assert!(!m.violates_threshold);
    }

    #[test]
    fn disparate_impact_below_eighty_percent_violates() {
        let mut c = RawlsCounters::default();
        // Privileged: 90% favorável (90/100).
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Favorable, 90);
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Unfavorable, 10);
        // Unprivileged: 50% favorável (50/100) → DIR = 0.555 < 0.80.
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Favorable, 50);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Unfavorable, 50);

        let m = compute_dir(&c, DEFAULT_DIR_THRESHOLD);
        assert!(!m.insufficient_samples);
        assert!(m.violates_threshold);
        assert!(m.dir < DEFAULT_DIR_THRESHOLD);
        assert!((m.dir - (50.0 / 100.0) / (90.0 / 100.0)).abs() < 1e-9);
    }

    #[test]
    fn boundary_at_threshold_does_not_violate() {
        let mut c = RawlsCounters::default();
        // Privileged: 100% favorável. Unprivileged: 80% favorável.
        // DIR = 0.80 (exatamente no threshold) — convenção: NÃO viola
        // (regra dos 4/5 usa `< 0.80`, não `≤ 0.80`).
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Favorable, 100);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Favorable, 80);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Unfavorable, 20);

        let m = compute_dir(&c, DEFAULT_DIR_THRESHOLD);
        assert!(!m.violates_threshold);
        assert!((m.dir - 0.80).abs() < 1e-9);
    }

    #[test]
    fn unclassified_does_not_affect_dir() {
        let mut c = RawlsCounters::default();
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Favorable, 80);
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Unfavorable, 20);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Favorable, 80);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Unfavorable, 20);
        // Mil eventos Unclassified — não devem mover o DIR.
        record_n(&mut c, GroupClass::Unclassified, OutcomeBucket::Favorable, 1000);

        let m = compute_dir(&c, DEFAULT_DIR_THRESHOLD);
        assert!((m.dir - 1.0).abs() < 1e-9);
        assert_eq!(c.total_events, 1200);
        assert_eq!(c.privileged_total(), 100);
        assert_eq!(c.unprivileged_total(), 100);
    }

    #[test]
    fn privileged_zero_rate_falls_back_to_parity() {
        let mut c = RawlsCounters::default();
        // Privileged: 0% favorável. Sem o fallback, DIR seria infinito ou NaN.
        record_n(&mut c, GroupClass::Privileged, OutcomeBucket::Unfavorable, 100);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Favorable, 50);
        record_n(&mut c, GroupClass::Unprivileged, OutcomeBucket::Unfavorable, 50);

        let m = compute_dir(&c, DEFAULT_DIR_THRESHOLD);
        assert!((m.dir - 1.0).abs() < 1e-9);
        assert!(!m.violates_threshold);
    }

    #[test]
    fn monitor_records_and_retrieves_per_tenant() {
        let monitor = RawlsMonitor::new(DEFAULT_DIR_THRESHOLD);
        // Tenant A: paridade.
        for _ in 0..40 {
            monitor.record("acme", GroupClass::Privileged, OutcomeBucket::Favorable);
            monitor.record("acme", GroupClass::Unprivileged, OutcomeBucket::Favorable);
        }
        // Tenant B: disparate impact.
        for _ in 0..40 {
            monitor.record("globex", GroupClass::Privileged, OutcomeBucket::Favorable);
            monitor.record("globex", GroupClass::Unprivileged, OutcomeBucket::Unfavorable);
        }

        let acme = monitor.metrics("acme").expect("acme registered");
        let globex = monitor.metrics("globex").expect("globex registered");
        assert!(!acme.violates_threshold);
        assert!(globex.violates_threshold);
        assert!(monitor.metrics("nonexistent").is_none());
    }

    #[test]
    fn monitor_default_uses_eighty_percent_threshold() {
        let monitor = RawlsMonitor::default();
        assert!((monitor.threshold() - DEFAULT_DIR_THRESHOLD).abs() < 1e-9);
    }

    // ── ADR-0089 — remove_tenant + ReloadableGuardrail ────────────

    #[test]
    fn remove_tenant_clears_state_for_only_that_tenant() {
        let monitor = RawlsMonitor::default();
        for _ in 0..40 {
            monitor.record("a", GroupClass::Privileged, OutcomeBucket::Favorable);
            monitor.record("a", GroupClass::Unprivileged, OutcomeBucket::Favorable);
            monitor.record("b", GroupClass::Privileged, OutcomeBucket::Favorable);
            monitor.record("b", GroupClass::Unprivileged, OutcomeBucket::Favorable);
        }
        assert!(monitor.metrics("a").is_some());
        assert!(monitor.metrics("b").is_some());

        let removed = monitor.remove_tenant("a");
        assert!(removed, "remove_tenant deve retornar true para tenant existente");
        assert!(monitor.metrics("a").is_none(), "tenant a deve estar removido");
        assert!(monitor.metrics("b").is_some(), "tenant b NÃO deve ser afetado");
    }

    #[test]
    fn remove_tenant_is_idempotent() {
        let monitor = RawlsMonitor::default();
        assert!(!monitor.remove_tenant("ghost"));
        assert!(!monitor.remove_tenant("ghost"));
    }

    #[test]
    fn reload_baseline_returns_not_applicable_for_rawls() {
        use crate::statistics::reloadable::{ReloadError, ReloadableGuardrail};
        let monitor = RawlsMonitor::default();
        let result = <RawlsMonitor as ReloadableGuardrail>::reload_baseline(
            &monitor, "any-tenant", "any: yaml",
        );
        assert_eq!(result, Err(ReloadError::NotApplicable));
    }

    #[test]
    fn rawls_implements_reloadable_via_dyn_dispatch() {
        use crate::statistics::reloadable::ReloadableGuardrail;
        let monitor: Box<dyn ReloadableGuardrail> = Box::new(RawlsMonitor::default());
        // remove_tenant via trait deve funcionar (true se algo removido).
        assert!(!monitor.remove_tenant("ghost"));
    }
}
