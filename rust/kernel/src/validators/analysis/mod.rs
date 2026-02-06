//! Analysis Validators Module
//!
//! Responsável pela detecção de anomalias estatísticas e heurísticas.
//! Este módulo consome as ferramentas matemáticas de `crate::statistics`.

pub mod anomaly;

// Re-exporta o Validador Estatístico Unificado para ser usado pelo Gatekeeper
pub use anomaly::StatisticalValidator;