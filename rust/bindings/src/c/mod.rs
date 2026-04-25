//! C FFI bindings for BuildToValue Governance
//!
//! Este módulo fornece funções exportáveis para C.
//! Use `cargo build --features c` para compilar.
//!
//! Phase 3: TechnicalEvidence expanded with risk_level, finding_count, critical_count.
//! C_API_VERSION bumped to 2.

pub mod ffi;
pub use ffi::*;

/// Phase 3: bumped from 1 to 2 after replacing stub risk=42 with real kernel.
pub const C_API_VERSION: u32 = 2;

/// Estrutura de retorno para evidências técnicas (C-compatible).
///
/// Phase 3: added risk_level, finding_count, critical_count fields.
/// All fields map directly from buildtovalue_kernel TechnicalEvidence.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TechnicalEvidence {
    pub protocol_version: u8,
    pub audit_trail_id: u128,
    pub timestamp: u64,
    pub evidence_hash: [u8; 32],
    /// Composite risk 0.0–1.0 scaled to 0–255 for C ABI compatibility.
    pub composite_risk: u8,
    /// Risk level: 0=Safe, 1=Low, 2=Medium, 3=High, 4=Critical.
    pub risk_level: u8,
    pub finding_count: u8,
    pub critical_count: u8,
    pub input_size: usize,
    pub processing_time_us: u64,
}

impl Default for TechnicalEvidence {
    fn default() -> Self {
        Self {
            protocol_version: 2,
            audit_trail_id: 0,
            timestamp: 0,
            evidence_hash: [0; 32],
            composite_risk: 0,
            risk_level: 0,
            finding_count: 0,
            critical_count: 0,
            input_size: 0,
            processing_time_us: 0,
        }
    }
}
