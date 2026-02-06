//! Core Module
//! Tipos fundamentais e erros compartilhados por todo o sistema.

pub mod types;
pub mod errors;

// Re-exports para facilitar o uso
pub use types::{ValidatorModule, TechnicalSeverity, Action, RiskLevel};
pub use errors::EvidenceError;