//! BuildToValue Sovereign Kernel v2.2.0
//!
//! Rust-based ethical governance kernel for AI agents.
//! Implements Evidence Protocol v2.1 with < 50ms p99 latency.

// ═══════════════════════════════════════════════════════════════════════════
// CORE STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

pub mod technical_evidence;
pub mod finding;
pub mod types;

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION MODULES
// ═══════════════════════════════════════════════════════════════════════════

pub mod validators;

// ═══════════════════════════════════════════════════════════════════════════
// STATISTICAL ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

pub mod statistics;

// ═══════════════════════════════════════════════════════════════════════════
// DEOBFUSCATION
// ═══════════════════════════════════════════════════════════════════════════

pub mod deobfuscator;

// ═══════════════════════════════════════════════════════════════════════════
// LEDGER & DURABILITY
// ═══════════════════════════════════════════════════════════════════════════

pub mod ledger;

// ═══════════════════════════════════════════════════════════════════════════
// COMPLIANCE & POLICIES
// ═══════════════════════════════════════════════════════════════════════════

pub mod compliance;

// ═══════════════════════════════════════════════════════════════════════════
// SECURITY
// ═══════════════════════════════════════════════════════════════════════════

pub mod security;

// ═══════════════════════════════════════════════════════════════════════════
// ORCHESTRATION
// ═══════════════════════════════════════════════════════════════════════════

pub mod gatekeeper;

// ═══════════════════════════════════════════════════════════════════════════
// OBSERVABILITY
// ═══════════════════════════════════════════════════════════════════════════

pub mod observability;

// ═══════════════════════════════════════════════════════════════════════════
// FFI BINDINGS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "pyo3")]
pub mod bindings_python;

#[cfg(feature = "c-bindings")]
pub mod bindings_c;

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests;

// ═══════════════════════════════════════════════════════════════════════════
// RE-EXPORTS (PUBLIC API)
// ═══════════════════════════════════════════════════════════════════════════

pub use technical_evidence::TechnicalEvidence;
pub use finding::Finding;
pub use types::{ValidatorModule, TechnicalSeverity, InputStatistics, BiasDeclaration};
pub use gatekeeper::Gatekeeper;
pub use ledger::{LedgerEntry, DurableLedger, WriteAheadLog};

// ═══════════════════════════════════════════════════════════════════════════
// VERSION INFO
// ═══════════════════════════════════════════════════════════════════════════

pub const VERSION: &str = "2.2.0";
pub const PROTOCOL_VERSION: u16 = 2;


//! BuildToValue Rust Kernel
//!
//! Sovereign Trust OS - Core execution engine

// Módulos públicos
pub mod finding;
pub mod types;
pub mod validators;
pub mod statistics;
pub mod gatekeeper;
pub mod ledger;
pub mod ffi_security;  // NOVO: Day 2

// Re-exports públicos
pub use finding::{Finding, FindingBuilder};
pub use types::{TechnicalEvidence, RiskLevel};
pub use gatekeeper::Gatekeeper;
pub use ledger::DurableLedger;
pub use ffi_security::{FFIBuffer, FFIBatchProcessor, FFIError};  // NOVO

// ═══════════════════════════════════════════════════════════════════════════
// VERSÃO
// ═══════════════════════════════════════════════════════════════════════════

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_DATE: &str = env!("VERGEN_BUILD_TIMESTAMP");
pub const GIT_SHA: &str = env!("VERGEN_GIT_SHA");

/// Retorna informações de versão.
pub fn version_info() -> String {
    format!(
        "BuildToValue Kernel v{} ({})\nGit: {}\nBuild: {}",
        VERSION,
        env!("TARGET"),
        GIT_SHA,
        BUILD_DATE
    )
}

//! BuildToValue Rust Kernel v2.0

pub mod finding;
pub mod types;
pub mod validators;
pub mod statistics;
pub mod gatekeeper;
pub mod ledger;
pub mod ffi_security;
pub mod remote_sync;  // NOVO: Day 9

// Re-exports
pub use finding::{Finding, FindingBuilder};
pub use types::{TechnicalEvidence, RiskLevel};
pub use gatekeeper::Gatekeeper;
pub use ledger::{DurableLedger, WalEntry};
pub use ffi_security::{FFIBuffer, FFIBatchProcessor, FFIError};
pub use remote_sync::{RemoteSyncService, RemoteConfig, create_remote_sync};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
