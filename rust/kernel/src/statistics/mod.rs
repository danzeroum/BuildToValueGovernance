//! Statistics Module v2.3.2
//!
//! Fornece análises estatísticas (entropia, z-score, proporções).
//! Re-exporta os tipos principais.

pub mod char_ratio;
pub mod entropy;
pub mod zscore;

pub use char_ratio::CharRatioAnalyzer;
pub use entropy::EntropyCalculator;
pub use zscore::ZScoreCalculator;

// Re-exports para uso externo
pub use crate::core::types::InputStatistics;
pub use crate::evidence::Finding;pub mod language;
pub use language::LanguageDetector;
