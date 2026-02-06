//! FFI Module
//! Interfaces para linguagens externas (C, Python).

pub mod bridge;
pub mod validators_ffi;

pub use bridge::{RustKernel, PyTechnicalEvidence};
pub use validators_ffi::{
    validate_consent, validate_consent_revocation,
    validate_sensitive_data, validate_batch, free_validation_result
};