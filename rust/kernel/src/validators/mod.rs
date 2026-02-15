//! Validators Module v2.3.2
//!
//! Padronização da interface de validação.

pub mod brazilian;
pub mod financial;
pub mod communication;
pub mod network;
pub mod sensitive;
pub mod privacy;
pub mod analysis;

// Re-exports
pub use brazilian::{CpfValidator, CnpjValidator};
pub use financial::CreditCardValidator;
pub use communication::{EmailValidator, PhoneValidator};
pub use network::{Ipv4Validator, UrlValidator};
pub use sensitive::SensitiveDataValidator;
pub use privacy::{ConsentValidator, ConsentRevocationValidator};
pub use analysis::StatisticalValidator;

use crate::evidence::Finding;
use crate::core::types::BiasDeclaration;

/// Trait original para validadores (mantido por compatibilidade, mas obsoleto).
/// Novos módulos devem implementar `crate::core::module::Module` diretamente.
pub trait Validator: Send + Sync {
    /// Valida input e retorna findings.
    fn validate(&self, input: &str) -> Vec<Finding>;

    /// Declaração de viés do validador (Opcional, padrão vazio).
    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::default()
    }
}