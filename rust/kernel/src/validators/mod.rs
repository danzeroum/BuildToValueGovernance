//! Validators Module v2.5.0 (ADR-017)
//!
//! O trait `Validator` é mantido por compatibilidade mas está OBSOLETO.
//! Todos os módulos devem implementar `crate::core::module::Module`.

pub mod brazilian;
pub mod financial;
pub mod communication;
pub mod network;
pub mod us;
pub mod uk;
pub mod eu;
pub mod sensitive;
pub mod privacy;
pub mod analysis;

pub use brazilian::{CpfValidator, CnpjValidator};
pub use financial::CreditCardValidator;
pub use communication::{EmailValidator, PhoneValidator};
pub use network::{Ipv4Validator, UrlValidator};
pub use us::SsnValidator;
pub use uk::NhsValidator;
pub use eu::{VatValidator, IbanValidator};
pub use sensitive::SensitiveDataValidator;
pub use privacy::{ConsentValidator, ConsentRevocationValidator};
pub use analysis::StatisticalValidator;

use crate::evidence::Finding;
use crate::core::types::BiasDeclaration;

/// OBSOLETO — usar `crate::core::module::Module`.
/// Mantido apenas para não quebrar LGPD validators (consent, sensitive, privacy)
/// que ainda não migraram para Module.
pub trait Validator: Send + Sync {
    fn validate(&self, input: &str) -> Vec<Finding>;

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::default()
    }
}