//! FFI Entrypoints — DEPRECATED (Phase 4)
//!
//! Phase 4: All functionality merged into bridge.rs.
//! This file is kept as a compatibility shim for any code that imports
//! from this path directly. In a future cleanup, this file can be deleted
//! and all imports updated to use `ffi::bridge::*`.
//!
//! The `btv_kernel` #[pymodule] has been REMOVED.
//! Use `buildtovalue_kernel` instead (defined in bridge.rs).

#![cfg(feature = "ffi-bindings")]

// Re-export everything from bridge — single source of truth
pub use super::bridge::*;

/// DEPRECATED: Use buildtovalue_kernel.update_accumulator_config() instead.
#[allow(unused_imports)]
pub use super::bridge::update_accumulator_config;
