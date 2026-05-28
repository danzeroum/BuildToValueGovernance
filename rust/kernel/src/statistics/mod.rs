//! Statistics Module v2.3.2
//!
//! Fornece análises estatísticas (entropia, z-score, proporções).
//! Re-exporta os tipos principais.

pub mod char_ratio;
pub mod entropy;
pub mod zscore;
pub mod rawls; // ADR-0086: Disparate Impact Monitor

pub use char_ratio::CharRatioAnalyzer;
pub use entropy::EntropyCalculator;
pub use zscore::ZScoreCalculator;
pub use rawls::{
    compute_dir, FairnessMetrics, GroupClass, OutcomeBucket, RawlsCounters,
    RawlsMonitor, DEFAULT_DIR_THRESHOLD, RAWLS_MIN_SAMPLES_PER_GROUP, RAWLS_WINDOW_SIZE,
};

// Re-exports para uso externo
pub use crate::core::types::InputStatistics;
pub use crate::evidence::Finding;
pub mod language;
pub use language::LanguageDetector;
