//! Core Module v1.1.0
//! Tipos fundamentais, erros e adapter de entrada compartilhados por todo o sistema.

pub mod types;
pub mod errors;
pub mod module;
pub mod adapter;

// Re-exports para facilitar o uso
pub use types::{ValidatorModule, TechnicalSeverity, Action, RiskLevel, BiasDeclaration};
pub use errors::EvidenceError;
pub use module::{Module, ScanContext};
pub use adapter::{adapt, AdaptedInput, AdaptError, MAX_INPUT_BYTES};
