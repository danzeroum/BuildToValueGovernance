//! Per-tenant state, baseline loader, and monitor for the Jonas PSI engine
//! (ADR-0087, Commits 3 & 4).
//!
//! - `JonasBaseline` — proporções de referência aprovadas pelo DPO, com hash
//!   SHA-256 do conteúdo para rastreabilidade no laudo.
//! - `JonasBaselineLoader::from_yaml_str` — parsing + validação (count,
//!   sum ≈ 1.0, todos os valores em [0, 1]).
//! - `TenantJonasState` — buffer FIFO, contador atômico, última métrica.
//!   Não deriva `Clone` (carrega `Mutex` e `AtomicU64`).
//! - `JonasMonitor` — `RwLock<HashMap<tenant_id, TenantJonasState>>`,
//!   paralelo ao `RawlsMonitor` (ver ADR-0087 §D5).
//!
//! Fail-safe: tenant sem baseline registrado → `record()` é noop, `metrics()`
//! retorna `DriftMetrics::disabled()`. Jonas nunca derruba a requisição.

use crate::statistics::jonas::{
    compute_psi, histogram_from_scores, DriftMetrics, PsiError, JONAS_BUFFER_CAPACITY,
    JONAS_COMPUTE_INTERVAL,
};
#[cfg(test)]
use crate::statistics::jonas::DriftAlert;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Erro do `JonasBaselineLoader`.
#[derive(Debug, Clone, PartialEq)]
pub enum BaselineError {
    /// YAML malformado ou faltando campos obrigatórios.
    ParseError(String),
    /// `count(reference_proportions) != bins`.
    BinCountMismatch { declared: usize, actual: usize },
    /// `|sum - 1.0| > 1e-6`.
    InvalidSum(f64),
    /// Alguma proporção fora de `[0.0, 1.0]`.
    OutOfRangeProportion(f64),
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(s) => write!(f, "baseline YAML parse error: {s}"),
            Self::BinCountMismatch { declared, actual } => write!(
                f,
                "bin count mismatch: declared={declared} reference_proportions.len()={actual}"
            ),
            Self::InvalidSum(s) => write!(
                f,
                "reference_proportions must sum to 1.0 ± 1e-6, got {s}"
            ),
            Self::OutOfRangeProportion(p) => {
                write!(f, "proportion {p} out of range [0.0, 1.0]")
            }
        }
    }
}

impl std::error::Error for BaselineError {}

/// Esquema YAML do baseline (ADR-0087 §D2).
#[derive(Debug, Deserialize)]
struct BaselineYaml {
    version: String,
    model_id: String,
    bins: usize,
    reference_proportions: Vec<f64>,
}

/// Baseline aprovado pelo DPO. Imutável após `from_yaml_str`.
#[derive(Debug, Clone)]
pub struct JonasBaseline {
    pub version: String,
    pub model_id: String,
    pub bins: usize,
    pub reference_proportions: Vec<f64>,
    /// SHA-256 hex do conteúdo YAML — propagado para
    /// `ExplainDecision.stages.jonas.baseline_hash` (ADR-0087 §D2,
    /// Reviewer 2 §8).
    pub baseline_hash: String,
}

/// Loader de baseline a partir de string YAML.
pub struct JonasBaselineLoader;

impl JonasBaselineLoader {
    /// Parseia e valida um baseline a partir de uma string YAML.
    /// O hash SHA-256 é calculado sobre o conteúdo bruto recebido — qualquer
    /// alteração no YAML, mesmo de comentários, produz um hash diferente.
    pub fn from_yaml_str(yaml_content: &str) -> Result<JonasBaseline, BaselineError> {
        let parsed: BaselineYaml = serde_yaml::from_str(yaml_content)
            .map_err(|e| BaselineError::ParseError(e.to_string()))?;

        if parsed.reference_proportions.len() != parsed.bins {
            return Err(BaselineError::BinCountMismatch {
                declared: parsed.bins,
                actual: parsed.reference_proportions.len(),
            });
        }

        for &p in &parsed.reference_proportions {
            if !(0.0..=1.0).contains(&p) {
                return Err(BaselineError::OutOfRangeProportion(p));
            }
        }

        let sum: f64 = parsed.reference_proportions.iter().sum();
        if (sum - 1.0).abs() > 1e-6 {
            return Err(BaselineError::InvalidSum(sum));
        }

        let hash = Sha256::digest(yaml_content.as_bytes());
        let baseline_hash = hex::encode(hash);

        Ok(JonasBaseline {
            version: parsed.version,
            model_id: parsed.model_id,
            bins: parsed.bins,
            reference_proportions: parsed.reference_proportions,
            baseline_hash,
        })
    }
}

/// Estado por tenant. Não derivar `Clone` — `Mutex` e `AtomicU64` impedem
/// clonagem segura. Acesso é sempre via referência através do `RwLock`
/// do `HashMap` do `JonasMonitor`.
pub struct TenantJonasState {
    buffer: Mutex<VecDeque<f64>>,
    tx_since_compute: AtomicU64,
    last_metrics: Mutex<Option<DriftMetrics>>,
    baseline: Arc<JonasBaseline>,
}

impl TenantJonasState {
    fn new(baseline: Arc<JonasBaseline>) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(JONAS_BUFFER_CAPACITY)),
            tx_since_compute: AtomicU64::new(0),
            last_metrics: Mutex::new(None),
            baseline,
        }
    }

    /// Registra um score (`[0.0, 1.0]`, clamped). Incrementa o contador
    /// atômico e, se atingiu `JONAS_COMPUTE_INTERVAL`, dispara o
    /// recálculo síncrono in-place (D6).
    fn record(&self, score: f64, score_unavailable: bool) {
        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() == JONAS_BUFFER_CAPACITY {
                buf.pop_front();
            }
            buf.push_back(score.clamp(0.0, 1.0));
        }

        let n = self.tx_since_compute.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= JONAS_COMPUTE_INTERVAL {
            // Reset best-effort: se outro thread chegou aqui antes, os dois
            // recalculam — trabalho duplicado raro, sem corrupção.
            self.tx_since_compute.store(0, Ordering::Relaxed);
            self.recompute(score_unavailable);
        }
    }

    fn recompute(&self, score_unavailable: bool) {
        let snapshot: Vec<f64> = match self.buffer.lock() {
            Ok(g) => g.iter().copied().collect(),
            Err(_) => return,
        };
        let counts = histogram_from_scores(&snapshot, self.baseline.bins);
        let metrics = compute_psi(&counts, &self.baseline.reference_proportions, score_unavailable)
            .unwrap_or_else(|_| DriftMetrics::disabled());
        if let Ok(mut last) = self.last_metrics.lock() {
            *last = Some(metrics);
        }
    }

    fn snapshot_metrics(&self) -> Option<DriftMetrics> {
        self.last_metrics.lock().ok().and_then(|g| g.clone())
    }
}

/// Monitor global. Estrutura paralela ao `RawlsMonitor` (ADR-0087 §D5).
pub struct JonasMonitor {
    tenants: RwLock<HashMap<String, TenantJonasState>>,
}

impl Default for JonasMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl JonasMonitor {
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Registra (e armazena) o baseline para um tenant. Deve ser chamado no
    /// boot do gateway, uma vez por tenant. Reimplementar para o mesmo
    /// tenant **substitui** o baseline existente — usado por futuro endpoint
    /// `/internal/v1/reload-policy`.
    pub fn install_baseline(&self, tenant_id: &str, baseline: JonasBaseline) {
        let Ok(mut guard) = self.tenants.write() else {
            return;
        };
        guard.insert(
            tenant_id.to_string(),
            TenantJonasState::new(Arc::new(baseline)),
        );
    }

    /// Registra uma decisão. Fail-safe — tenant sem baseline = noop.
    pub fn record(&self, tenant_id: &str, score: f64, score_unavailable: bool) {
        if let Ok(guard) = self.tenants.read() {
            if let Some(state) = guard.get(tenant_id) {
                state.record(score, score_unavailable);
            }
        }
    }

    /// Última métrica calculada para o tenant. `None` se o tenant não tem
    /// baseline ou ainda não atingiu o primeiro intervalo de cálculo.
    pub fn metrics(&self, tenant_id: &str) -> Option<DriftMetrics> {
        let guard = self.tenants.read().ok()?;
        let state = guard.get(tenant_id)?;
        state.snapshot_metrics()
    }

    /// Força recálculo síncrono — usado por testes e endpoint de telemetria.
    /// `Some(Ok(metrics))` se o tenant tem baseline; `Some(Err(PsiError))`
    /// se o cálculo matemático falhar; `None` se o tenant não está registrado.
    pub fn force_recompute(
        &self,
        tenant_id: &str,
        score_unavailable: bool,
    ) -> Option<Result<DriftMetrics, PsiError>> {
        let guard = self.tenants.read().ok()?;
        let state = guard.get(tenant_id)?;
        let snapshot: Vec<f64> = state.buffer.lock().ok()?.iter().copied().collect();
        let counts = histogram_from_scores(&snapshot, state.baseline.bins);
        let result = compute_psi(
            &counts,
            &state.baseline.reference_proportions,
            score_unavailable,
        );
        if let Ok(ref m) = result {
            if let Ok(mut last) = state.last_metrics.lock() {
                *last = Some(m.clone());
            }
        }
        Some(result)
    }

    /// Retorna `DriftMetrics::disabled()` quando o tenant não tem baseline.
    /// Útil para o Gatekeeper compor o laudo sem ramos especiais.
    pub fn metrics_or_disabled(&self, tenant_id: &str) -> DriftMetrics {
        self.metrics(tenant_id).unwrap_or_else(DriftMetrics::disabled)
    }

    /// Remove o estado do tenant (buffer + métricas + baseline).
    /// Idempotente. Fail-safe em lock poison (retorna false).
    /// Ver ADR-0089 §D3.
    pub fn remove_tenant(&self, tenant_id: &str) -> bool {
        let Ok(mut guard) = self.tenants.write() else {
            return false;
        };
        guard.remove(tenant_id).is_some()
    }
}

impl crate::statistics::reloadable::ReloadableGuardrail for JonasMonitor {
    /// Parse YAML via `JonasBaselineLoader` e instala — substitui baseline
    /// existente para o tenant, conforme `install_baseline()`.
    /// `yaml_content` vem do gateway que leu `policies/{tenant_id}/drift_baseline.yaml`.
    fn reload_baseline(
        &self,
        tenant_id: &str,
        yaml_content: &str,
    ) -> Result<(), crate::statistics::reloadable::ReloadError> {
        use crate::statistics::reloadable::ReloadError;
        let baseline = JonasBaselineLoader::from_yaml_str(yaml_content)
            .map_err(|e| ReloadError::InvalidYaml(e.to_string()))?;
        self.install_baseline(tenant_id, baseline);
        Ok(())
    }

    fn remove_tenant(&self, tenant_id: &str) -> bool {
        JonasMonitor::remove_tenant(self, tenant_id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
version: "1.0.0"
model_id: "creditscore-v3.2.1"
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

    #[test]
    fn valid_baseline_parses_with_hash() {
        let baseline = JonasBaselineLoader::from_yaml_str(VALID_YAML).expect("parse");
        assert_eq!(baseline.bins, 10);
        assert_eq!(baseline.reference_proportions.len(), 10);
        assert_eq!(baseline.model_id, "creditscore-v3.2.1");
        assert_eq!(baseline.version, "1.0.0");
        assert_eq!(baseline.baseline_hash.len(), 64);
        assert!(baseline.baseline_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn baseline_hash_changes_on_content_change() {
        let yaml_b = VALID_YAML.replace("1.0.0", "1.0.1");
        let a = JonasBaselineLoader::from_yaml_str(VALID_YAML).unwrap();
        let b = JonasBaselineLoader::from_yaml_str(&yaml_b).unwrap();
        assert_ne!(a.baseline_hash, b.baseline_hash);
    }

    #[test]
    fn bin_count_mismatch_rejected() {
        let yaml = r#"
version: "1.0.0"
model_id: "m"
bins: 10
reference_proportions: [0.5, 0.5]
"#;
        let err = JonasBaselineLoader::from_yaml_str(yaml).unwrap_err();
        assert_eq!(
            err,
            BaselineError::BinCountMismatch {
                declared: 10,
                actual: 2,
            }
        );
    }

    #[test]
    fn invalid_sum_rejected() {
        let yaml = r#"
version: "1.0.0"
model_id: "m"
bins: 2
reference_proportions: [0.3, 0.3]
"#;
        let err = JonasBaselineLoader::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, BaselineError::InvalidSum(_)));
    }

    #[test]
    fn out_of_range_proportion_rejected() {
        let yaml = r#"
version: "1.0.0"
model_id: "m"
bins: 2
reference_proportions: [1.5, -0.5]
"#;
        let err = JonasBaselineLoader::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, BaselineError::OutOfRangeProportion(_)));
    }

    #[test]
    fn malformed_yaml_returns_parse_error() {
        let err = JonasBaselineLoader::from_yaml_str("::not yaml::").unwrap_err();
        assert!(matches!(err, BaselineError::ParseError(_)));
    }

    fn make_baseline() -> JonasBaseline {
        JonasBaselineLoader::from_yaml_str(VALID_YAML).unwrap()
    }

    #[test]
    fn unregistered_tenant_records_noop() {
        let monitor = JonasMonitor::new();
        monitor.record("ghost", 0.7, false);
        assert!(monitor.metrics("ghost").is_none());
    }

    #[test]
    fn metrics_or_disabled_returns_disabled_for_unknown_tenant() {
        let monitor = JonasMonitor::new();
        let m = monitor.metrics_or_disabled("ghost");
        assert_eq!(m.alert, DriftAlert::Disabled);
        assert!(m.psi.is_nan());
    }

    #[test]
    fn force_recompute_below_min_samples_is_warmup() {
        let monitor = JonasMonitor::new();
        monitor.install_baseline("acme", make_baseline());
        for i in 0..100 {
            let score = ((i as f64) % 10.0) / 10.0 + 0.05;
            monitor.record("acme", score, false);
        }
        let result = monitor
            .force_recompute("acme", false)
            .expect("tenant present")
            .expect("psi computes");
        assert_eq!(result.alert, DriftAlert::WarmUp);
        assert!(result.psi.is_finite());
    }

    #[test]
    fn force_recompute_with_drift_triggers_critical() {
        let monitor = JonasMonitor::new();
        monitor.install_baseline("globex", make_baseline());
        for _ in 0..600 {
            monitor.record("globex", 0.05, false);
        }
        let result = monitor
            .force_recompute("globex", false)
            .expect("tenant present")
            .expect("psi computes");
        assert_eq!(
            result.alert,
            DriftAlert::Critical,
            "drift severo deve disparar Critical, psi={}",
            result.psi
        );
        assert!(result.psi >= 0.25);
    }

    #[test]
    fn auto_compute_fires_after_compute_interval() {
        let monitor = JonasMonitor::new();
        monitor.install_baseline("auto", make_baseline());

        for i in 0..(JONAS_COMPUTE_INTERVAL - 1) {
            monitor.record("auto", (i as f64 % 10.0) / 10.0 + 0.05, false);
        }
        assert!(monitor.metrics("auto").is_none());

        monitor.record("auto", 0.55, false);
        let m = monitor.metrics("auto").expect("metrics installed");
        assert!(m.psi.is_finite());
    }

    #[test]
    fn install_baseline_replaces_existing() {
        let monitor = JonasMonitor::new();
        monitor.install_baseline("t", make_baseline());
        for _ in 0..600 {
            monitor.record("t", 0.05, false);
        }
        let before = monitor
            .force_recompute("t", false)
            .expect("tenant present")
            .expect("compute");
        assert!(before.window_size > 0);

        monitor.install_baseline("t", make_baseline());
        let after = monitor.metrics("t");
        assert!(after.is_none(), "metrics must reset after reinstall");
    }

    #[test]
    fn tenants_are_isolated() {
        let monitor = JonasMonitor::new();
        monitor.install_baseline("a", make_baseline());
        monitor.install_baseline("b", make_baseline());

        for _ in 0..600 {
            monitor.record("a", 0.05, false);
        }
        let m_a = monitor
            .force_recompute("a", false)
            .expect("a present")
            .expect("psi a");
        let m_b = monitor.metrics("b");
        assert_eq!(m_a.alert, DriftAlert::Critical);
        assert!(m_b.is_none(), "tenant b never recorded — no metrics");
    }

    #[test]
    fn ring_buffer_does_not_exceed_capacity() {
        let monitor = JonasMonitor::new();
        monitor.install_baseline("bounded", make_baseline());
        for i in 0..(JONAS_BUFFER_CAPACITY + 500) {
            monitor.record("bounded", (i as f64 % 100.0) / 100.0, false);
        }
        let m = monitor
            .force_recompute("bounded", false)
            .expect("tenant present")
            .expect("psi");
        assert!(m.window_size <= JONAS_BUFFER_CAPACITY);
    }

    // ── ADR-0089 — remove_tenant + reload via trait ───────────────

    #[test]
    fn remove_tenant_clears_state_and_is_isolated() {
        let monitor = JonasMonitor::new();
        monitor.install_baseline("a", make_baseline());
        monitor.install_baseline("b", make_baseline());
        for _ in 0..600 {
            monitor.record("a", 0.05, false);
            monitor.record("b", 0.05, false);
        }
        let _ = monitor.force_recompute("a", false);
        let _ = monitor.force_recompute("b", false);
        assert!(monitor.metrics("a").is_some());
        assert!(monitor.metrics("b").is_some());

        let removed = monitor.remove_tenant("a");
        assert!(removed);
        assert!(monitor.metrics("a").is_none());
        assert!(
            monitor.metrics("b").is_some(),
            "tenant b deve permanecer intacto"
        );
    }

    #[test]
    fn remove_tenant_idempotent_in_jonas() {
        let monitor = JonasMonitor::new();
        assert!(!monitor.remove_tenant("ghost"));
    }

    #[test]
    fn reload_baseline_via_trait_installs_then_records_work() {
        use crate::statistics::reloadable::ReloadableGuardrail;
        let monitor = JonasMonitor::new();
        // Antes do reload: tenant não tem baseline.
        monitor.record("acme", 0.5, false);
        assert!(monitor.metrics("acme").is_none());

        let result = <JonasMonitor as ReloadableGuardrail>::reload_baseline(
            &monitor, "acme", VALID_YAML,
        );
        assert!(result.is_ok());
        // Após reload, install_baseline foi chamado — buffer foi resetado.
        // Novos records contribuem para um cálculo válido.
        for _ in 0..600 {
            monitor.record("acme", 0.5, false);
        }
        let m = monitor
            .force_recompute("acme", false)
            .expect("acme present")
            .expect("psi");
        assert!(m.psi.is_finite());
    }

    #[test]
    fn reload_baseline_with_invalid_yaml_returns_error() {
        use crate::statistics::reloadable::{ReloadError, ReloadableGuardrail};
        let monitor = JonasMonitor::new();
        let result = <JonasMonitor as ReloadableGuardrail>::reload_baseline(
            &monitor, "tenant", "::not yaml::",
        );
        assert!(matches!(result, Err(ReloadError::InvalidYaml(_))));
    }

    #[test]
    fn jonas_implements_reloadable_via_dyn_dispatch() {
        use crate::statistics::reloadable::ReloadableGuardrail;
        let monitor: Box<dyn ReloadableGuardrail> = Box::new(JonasMonitor::new());
        assert!(!monitor.remove_tenant("ghost"));
        let r = monitor.reload_baseline("acme", VALID_YAML);
        assert!(r.is_ok());
    }
}
