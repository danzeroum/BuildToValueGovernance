//! BuildToValue Sovereign Kernel v1

pub mod api;
pub mod batch;
pub mod compliance;
pub mod core;
pub mod deobfuscator;
pub mod evidence;
pub mod gatekeeper;
pub mod interceptor;
pub mod ledger;
pub mod network;
pub mod output_guard;
pub mod policy;
pub mod session_guard;
pub mod statistics;
pub mod validators;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;

#[cfg(feature = "observability")]
pub mod observability;

// Re-exports
pub use gatekeeper::Gatekeeper;
pub use evidence::{TechnicalEvidence, Finding};
pub use core::types::{ValidatorModule, TechnicalSeverity, Action, RiskLevel, BiasDeclaration};
pub use validators::Validator;

pub const KERNEL_VERSION: &str = "1.0.0";
pub const PROJECT_VERSION: &str = "1.0";
pub const PROTOCOL_VERSION: u16 = 3;

// Adicionar em rust/kernel/src/lib.rs

pub mod security {
    pub mod prompt_injection;
    pub mod pattern_registry;
    pub mod supply_guard;
    pub mod audit;
    pub mod output_guard;
    pub mod session_guard;
    pub mod skill_registry;
    pub mod signing;
}

pub fn version_info() -> String {
    format!(
        "BuildToValue v{} (Kernel v{}, Protocol v{})",
        PROJECT_VERSION,
        KERNEL_VERSION,
        PROTOCOL_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(info.contains("BuildToValue v1.0"));
        assert!(info.contains("Kernel v1.0.0"));
    }
}