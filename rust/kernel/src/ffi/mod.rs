//! FFI Module v3.0 — Consolidated
//! Interfaces para linguagens externas (C, Python).
//!
//! Phase 4: kernel_ffi is now a deprecation shim. All real exports
//! come from bridge.rs. Single #[pymodule]: buildtovalue_kernel.

pub mod bridge;
pub mod validators_ffi;
pub mod goal_drift_ffi;

pub use bridge::{
    RustKernel, PyTechnicalEvidence, PyBiasDeclaration, PyBatchResult,
    version,
};
pub use validators_ffi::{
    validate_consent, validate_consent_revocation,
    validate_sensitive_data, validate_batch, free_validation_result
};
