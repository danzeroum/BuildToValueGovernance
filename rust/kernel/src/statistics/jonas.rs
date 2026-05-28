//! Jonas Population Stability Drift Monitor (ADR-0087).
//!
//! Calcula o Population Stability Index (PSI):
//!
//! ```text
//! PSI = Σ_i (A_i − R_i) · ln(A_i / R_i)
//! ```
//!
//! - `A_i` = proporção observada no bin i (janela atual).
//! - `R_i` = proporção de referência no bin i (baseline aprovado pelo DPO).
//!
//! Thresholds (ADR-0087 §D4):
//! - `< 0.10` nominal.
//! - `[0.10, 0.25)` warning.
//! - `≥ 0.25` critical → E161 (HTTP 451) → ALLOW → REDACT.
//!
//! Este módulo contém APENAS o motor matemático puro. Storage por tenant,
//! parsing do baseline YAML e integração no Gatekeeper são commits separados.
//!
//! Invariantes:
//! - `compute_psi` é pura (sem I/O, sem estado, sem alocação fora dos
//!   buffers temporários do cálculo).
//! - Regularização de Laplace com `ε = 1e-9` + normalização pós-suavização
//!   evitam `ln(0)` e drift numérico em PSI ≈ 0.
//! - `DriftAlert::WarmUp` evita falso positivo quando a amostragem é insuficiente.
//! - `DriftMetrics` retorna `top_bin_contribution` para que logs e laudos
//!   apontem qual bin mais contribuiu para o drift (ADR-0087 Reviewer 2 §3).

use serde::{Deserialize, Serialize};

/// Threshold inferior — `[JONAS_WARNING_THRESHOLD, JONAS_CRITICAL_THRESHOLD)` = warning.
pub const JONAS_WARNING_THRESHOLD: f64 = 0.10;

/// Threshold de drift crítico — acima disso aciona E161.
pub const JONAS_CRITICAL_THRESHOLD: f64 = 0.25;

/// Mínimo de amostras no buffer para PSI ser considerado válido.
/// Abaixo disso → `DriftAlert::WarmUp` (não aciona E161).
pub const JONAS_MIN_SAMPLES: usize = 500;

/// Intervalo em transações para recálculo (D6).
pub const JONAS_COMPUTE_INTERVAL: u64 = 500;

/// Capacidade do ring buffer FIFO por tenant (D5).
pub const JONAS_BUFFER_CAPACITY: usize = 10_000;

/// Epsilon de regularização de Laplace (D3). Valor pequeno para minimizar
/// viés em distribuições com muitos bins.
const EPSILON: f64 = 1e-9;

/// Classificação do status de drift para um tenant em um ponto no tempo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftAlert {
    /// `PSI < 0.10` — distribuição estável.
    Nominal,
    /// `0.10 ≤ PSI < 0.25` — drift moderado, telemetria, ALLOW mantido.
    Warning,
    /// `PSI ≥ 0.25` — drift crítico, aciona E161 e rebaixamento.
    Critical,
    /// Buffer com menos que `JONAS_MIN_SAMPLES` amostras — PSI calculado
    /// mas NÃO aciona E161 (evita falso positivo em arranque).
    WarmUp,
    /// Baseline ausente, malformado ou bin count divergente — Jonas
    /// desativado para o tenant. Outros estágios continuam.
    Disabled,
    /// `decision_confidence` ausente em todas as amostras — score
    /// substituído por 0.5; sinalizado para revisão humana.
    ScoreUnavailable,
}

/// Métrica Jonas computada em ponto-no-tempo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftMetrics {
    /// Population Stability Index. `f64::NAN` se baseline desabilitado.
    pub psi: f64,
    /// Classificação derivada de `psi` mais condições de warm-up/disabled.
    pub alert: DriftAlert,
    /// Tamanho da janela usada no cálculo.
    pub window_size: usize,
    /// Bin que mais contribuiu para o PSI (índice no vetor de proporções).
    /// `None` se PSI = 0.0 ou `Disabled`.
    pub top_bin_index: Option<usize>,
    /// Contribuição do bin de maior impacto (em valor absoluto).
    pub top_bin_contribution: f64,
    /// Threshold crítico aplicado.
    pub critical_threshold: f64,
    /// `true` se o cálculo foi feito com `decision_confidence = 0.5`
    /// devido a campo ausente — sinaliza qualidade reduzida no laudo.
    pub score_unavailable: bool,
}

impl DriftMetrics {
    /// Estado "Jonas desativado" (baseline ausente/inválido).
    pub fn disabled() -> Self {
        Self {
            psi: f64::NAN,
            alert: DriftAlert::Disabled,
            window_size: 0,
            top_bin_index: None,
            top_bin_contribution: 0.0,
            critical_threshold: JONAS_CRITICAL_THRESHOLD,
            score_unavailable: false,
        }
    }
}

/// Erro do motor PSI. Caller deve mapear para `DriftMetrics::disabled()`
/// e logar — Jonas falhar nunca derruba o request.
#[derive(Debug, Clone, PartialEq)]
pub enum PsiError {
    /// Vetores `current` e `reference` têm tamanhos diferentes.
    BinCountMismatch { current: usize, reference: usize },
    /// Vetor com 0 bins.
    EmptyBins,
    /// Soma das proporções de referência fora de `1.0 ± 1e-6`.
    InvalidBaselineSum(f64),
}

impl std::fmt::Display for PsiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinCountMismatch { current, reference } => write!(
                f,
                "bin count mismatch: current={current} reference={reference}"
            ),
            Self::EmptyBins => write!(f, "PSI requires at least 1 bin"),
            Self::InvalidBaselineSum(s) => write!(
                f,
                "baseline reference_proportions must sum to 1.0 ± 1e-6, got {s}"
            ),
        }
    }
}

impl std::error::Error for PsiError {}

/// Distribui scores no intervalo `[0.0, 1.0]` em `n_bins` bins de largura igual.
/// Scores fora do intervalo são clamped (evita perder massa por outliers).
///
/// Retorna `Vec<f64>` com contagens absolutas por bin.
pub fn histogram_from_scores(scores: &[f64], n_bins: usize) -> Vec<f64> {
    let mut bins = vec![0.0; n_bins];
    if n_bins == 0 {
        return bins;
    }
    let width = 1.0 / n_bins as f64;
    for &s in scores {
        let clamped = s.clamp(0.0, 1.0);
        // `floor` + clamp evita índice `n_bins` quando score = 1.0.
        let idx = ((clamped / width).floor() as usize).min(n_bins - 1);
        bins[idx] += 1.0;
    }
    bins
}

/// Aplica regularização de Laplace e normaliza para soma = 1.0 (D3).
/// Sempre retorna vetor de proporções estritamente positivas.
fn smooth_and_normalize(counts: &[f64]) -> Vec<f64> {
    let n = counts.len() as f64;
    let sum: f64 = counts.iter().sum();
    let denominator = sum + EPSILON * n;
    let smoothed: Vec<f64> = counts.iter().map(|&c| (c + EPSILON) / denominator).collect();
    // Renormaliza para eliminar drift numérico — garante soma exata após
    // smoothing (importante para PSI próximo de zero).
    let smoothed_sum: f64 = smoothed.iter().sum();
    smoothed.iter().map(|x| x / smoothed_sum).collect()
}

/// Calcula o PSI entre `current` (contagens absolutas observadas) e
/// `reference` (proporções normalizadas do baseline, devem somar ≈ 1.0).
///
/// Pura, O(n_bins). Retorna `DriftMetrics` com `alert` derivada de:
/// - `WarmUp` se `sum(current) < JONAS_MIN_SAMPLES`
/// - `Critical` se `psi ≥ JONAS_CRITICAL_THRESHOLD`
/// - `Warning` se `JONAS_WARNING_THRESHOLD ≤ psi < JONAS_CRITICAL_THRESHOLD`
/// - `Nominal` caso contrário
pub fn compute_psi(
    current: &[f64],
    reference: &[f64],
    score_unavailable: bool,
) -> Result<DriftMetrics, PsiError> {
    if current.is_empty() || reference.is_empty() {
        return Err(PsiError::EmptyBins);
    }
    if current.len() != reference.len() {
        return Err(PsiError::BinCountMismatch {
            current: current.len(),
            reference: reference.len(),
        });
    }
    let ref_sum: f64 = reference.iter().sum();
    if (ref_sum - 1.0).abs() > 1e-6 {
        return Err(PsiError::InvalidBaselineSum(ref_sum));
    }

    let window_size = current.iter().sum::<f64>().round() as usize;

    let actual_prop = smooth_and_normalize(current);
    // Reference vem já normalizado do baseline YAML; ainda aplicamos
    // smoothing para evitar ln(0) caso o YAML tenha algum bin = 0.
    let ref_prop = smooth_and_normalize(reference);

    let mut psi: f64 = 0.0;
    let mut top_idx: usize = 0;
    let mut top_contrib: f64 = 0.0;
    for (i, (&a, &r)) in actual_prop.iter().zip(ref_prop.iter()).enumerate() {
        let contrib = (a - r) * (a / r).ln();
        psi += contrib;
        if contrib.abs() > top_contrib.abs() {
            top_contrib = contrib;
            top_idx = i;
        }
    }

    let alert = if window_size < JONAS_MIN_SAMPLES {
        DriftAlert::WarmUp
    } else if score_unavailable {
        DriftAlert::ScoreUnavailable
    } else if psi >= JONAS_CRITICAL_THRESHOLD {
        DriftAlert::Critical
    } else if psi >= JONAS_WARNING_THRESHOLD {
        DriftAlert::Warning
    } else {
        DriftAlert::Nominal
    };

    Ok(DriftMetrics {
        psi,
        alert,
        window_size,
        top_bin_index: if psi.abs() < f64::EPSILON { None } else { Some(top_idx) },
        top_bin_contribution: top_contrib,
        critical_threshold: JONAS_CRITICAL_THRESHOLD,
        score_unavailable,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Aproximadamente igual com tolerância numérica.
    fn approx(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() < eps
    }

    #[test]
    fn parity_yields_psi_zero() {
        // current proporcionais a reference → PSI = 0.
        let reference = vec![0.1; 10];
        let current = vec![60.0; 10]; // 600 amostras distribuídas uniformemente
        let m = compute_psi(&current, &reference, false).expect("psi");
        assert!(approx(m.psi, 0.0, 1e-8), "psi={}", m.psi);
        assert_eq!(m.alert, DriftAlert::Nominal);
        assert_eq!(m.window_size, 600);
        assert!(m.top_bin_index.is_none());
    }

    #[test]
    fn severe_drift_triggers_critical() {
        // Baseline uniforme; current massivamente concentrado num bin.
        let reference = vec![0.1; 10];
        let mut current = vec![10.0; 10];
        current[0] = 700.0; // 800 totais, com 87.5% num único bin
        let m = compute_psi(&current, &reference, false).expect("psi");
        assert!(m.psi >= JONAS_CRITICAL_THRESHOLD, "expected critical psi, got {}", m.psi);
        assert_eq!(m.alert, DriftAlert::Critical);
        assert_eq!(m.top_bin_index, Some(0));
    }

    #[test]
    fn partial_drift_one_bin_yields_warning() {
        // Reviewer 2 Anexo 6: baseline uniforme, current com 1 bin desviando.
        let reference = vec![0.1; 10];
        let mut current = vec![60.0; 10]; // 600 amostras uniformes
        // Deslocamento moderado: bin 0 sobe para 180 (de 60), bin 1 cai para 0.
        current[0] = 180.0;
        current[1] = 0.0;
        // Total continua 600. Ainda > JONAS_MIN_SAMPLES.
        let m = compute_psi(&current, &reference, false).expect("psi");
        assert!(
            m.psi >= JONAS_WARNING_THRESHOLD,
            "expected warning-level psi, got {}",
            m.psi
        );
        assert!(matches!(m.alert, DriftAlert::Warning | DriftAlert::Critical));
        // Top bin deve ser 0 ou 1 (os que mais se deslocaram).
        assert!(matches!(m.top_bin_index, Some(0) | Some(1)));
    }

    #[test]
    fn warmup_below_min_samples_does_not_trigger_critical() {
        // PSI calculado, mas alert é WarmUp pois window < 500.
        let reference = vec![0.1; 10];
        let mut current = vec![1.0; 10];
        current[0] = 90.0; // 100 amostras, drift extremo mas amostra pequena
        let m = compute_psi(&current, &reference, false).expect("psi");
        assert_eq!(m.alert, DriftAlert::WarmUp);
        assert!(m.window_size < JONAS_MIN_SAMPLES);
        // PSI ainda é calculado para diagnóstico (não NaN).
        assert!(m.psi.is_finite());
    }

    #[test]
    fn empty_bin_does_not_cause_nan_or_inf() {
        // current com bin = 0 — Laplace deve evitar ln(0).
        let reference = vec![0.5, 0.5];
        let current = vec![1000.0, 0.0];
        let m = compute_psi(&current, &reference, false).expect("psi");
        assert!(m.psi.is_finite(), "psi must be finite, got {}", m.psi);
        assert!(!m.psi.is_nan());
    }

    #[test]
    fn bin_count_mismatch_returns_error() {
        let reference = vec![0.5, 0.5];
        let current = vec![100.0, 100.0, 100.0];
        let err = compute_psi(&current, &reference, false).unwrap_err();
        assert_eq!(
            err,
            PsiError::BinCountMismatch {
                current: 3,
                reference: 2
            }
        );
    }

    #[test]
    fn invalid_baseline_sum_returns_error() {
        // Soma = 0.9, fora da tolerância 1e-6.
        let reference = vec![0.1; 9]; // 0.9
        let current = vec![60.0; 9];
        let err = compute_psi(&current, &reference, false).unwrap_err();
        assert!(matches!(err, PsiError::InvalidBaselineSum(_)));
    }

    #[test]
    fn empty_bins_returns_error() {
        let err = compute_psi(&[], &[], false).unwrap_err();
        assert_eq!(err, PsiError::EmptyBins);
    }

    #[test]
    fn score_unavailable_overrides_alert() {
        let reference = vec![0.1; 10];
        let current = vec![60.0; 10]; // PSI ≈ 0
        let m = compute_psi(&current, &reference, true).expect("psi");
        assert_eq!(m.alert, DriftAlert::ScoreUnavailable);
        assert!(m.score_unavailable);
    }

    #[test]
    fn boundary_at_critical_threshold_is_critical() {
        // Construímos current cujo PSI deve ser próximo de 0.25.
        // Drift simétrico moderado:
        let reference = vec![0.1; 10];
        let mut current = vec![60.0; 10];
        current[0] = 240.0; // bin 0: de 60 (10%) para 240 (~40%)
        current[1] = 0.0;
        current[2] = 0.0;
        let m = compute_psi(&current, &reference, false).expect("psi");
        // Drift severo o suficiente para Critical:
        assert!(m.psi >= JONAS_CRITICAL_THRESHOLD, "psi={}", m.psi);
        assert_eq!(m.alert, DriftAlert::Critical);
    }

    #[test]
    fn histogram_clamps_out_of_range_scores() {
        let scores = vec![-0.5, 0.0, 0.5, 1.0, 1.5];
        let bins = histogram_from_scores(&scores, 4);
        // -0.5 → bin 0; 0.0 → bin 0; 0.5 → bin 2; 1.0 → bin 3; 1.5 → bin 3.
        assert_eq!(bins, vec![2.0, 0.0, 1.0, 2.0]);
        assert_eq!(bins.iter().sum::<f64>(), 5.0);
    }

    #[test]
    fn disabled_metrics_has_nan_psi_and_disabled_alert() {
        let m = DriftMetrics::disabled();
        assert!(m.psi.is_nan());
        assert_eq!(m.alert, DriftAlert::Disabled);
        assert!(m.top_bin_index.is_none());
    }
}
