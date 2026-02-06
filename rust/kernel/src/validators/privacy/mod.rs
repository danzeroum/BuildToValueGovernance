//! Privacy Validators (LGPD Rights & Consent)
pub mod consent;
pub mod revocation;

pub use consent::ConsentValidator;
pub use revocation::ConsentRevocationValidator;