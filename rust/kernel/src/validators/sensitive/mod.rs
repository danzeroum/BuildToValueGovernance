//! Sensitive Data Validators
//! Detecta dados sensíveis conforme LGPD.

pub mod lgpd;
pub mod consent;
pub mod revocation;

pub use lgpd::SensitiveDataValidator;
pub use consent::ConsentValidator;
pub use revocation::ConsentRevocationValidator;
