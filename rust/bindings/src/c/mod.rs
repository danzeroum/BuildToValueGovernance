//! C FFI bindings for BuildToValue Governance
//!
//! Este módulo fornece funções exportáveis para C.
//! Use `cargo build --features c` para compilar.

pub mod ffi;
pub use ffi::*;

/// Versão da API C
pub const C_API_VERSION: u32 = 1;

/// Estrutura de retorno para evidências técnicas
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TechnicalEvidence {
    pub protocol_version: u8,
    pub audit_trail_id: u128,
    pub timestamp: u64,
    pub evidence_hash: [u8; 32],
    pub composite_risk: u8,
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
            input_size: 0,
            processing_time_us: 0,
        }
    }
}