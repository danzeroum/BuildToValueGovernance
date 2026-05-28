//! Statistics Module v2.3.2
//!
//! Fornece análises estatísticas (entropia, z-score, proporções).
//! Re-exporta os tipos principais.

pub mod char_ratio;
pub mod entropy;
pub mod zscore;
pub mod rawls;         // ADR-0086: Disparate Impact Monitor
pub mod jonas;         // ADR-0087: Population Stability Drift Monitor (engine)
pub mod jonas_monitor;        // ADR-0087: state + baseline loader (Commits 3 & 4)
pub mod fairness_composition; // ADR-0087: Rawls + Jonas composition (Commit 6)

pub use char_ratio::CharRatioAnalyzer;
pub use entropy::EntropyCalculator;
pub use zscore::ZScoreCalculator;
pub use rawls::{
    compute_dir, FairnessMetrics, GroupClass, OutcomeBucket, RawlsCounters,
    RawlsMonitor, DEFAULT_DIR_THRESHOLD, RAWLS_MIN_SAMPLES_PER_GROUP, RAWLS_WINDOW_SIZE,
};
pub use jonas::{
    compute_psi, histogram_from_scores, DriftAlert, DriftMetrics, PsiError,
    JONAS_BUFFER_CAPACITY, JONAS_COMPUTE_INTERVAL, JONAS_CRITICAL_THRESHOLD,
    JONAS_MIN_SAMPLES, JONAS_WARNING_THRESHOLD,
};
pub use jonas_monitor::{
    BaselineError, JonasBaseline, JonasBaselineLoader, JonasMonitor, TenantJonasState,
};
pub use fairness_composition::{compose_fairness_action, FairnessDecision};

// Re-exports para uso externo
pub use crate::core::types::InputStatistics;
pub use crate::evidence::Finding;
pub mod language;
pub use language::LanguageDetector;
