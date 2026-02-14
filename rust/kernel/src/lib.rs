//! BuildToValue Sovereign Kernel v2.3.2

pub mod api;
pub mod compliance;
pub mod core;
pub mod deobfuscator;
pub mod evidence;
pub mod gatekeeper;
pub mod ledger;
pub mod observability;
pub mod policy;
pub mod security;
pub mod statistics;
pub mod validators;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;

// Re-exports
pub use gatekeeper::Gatekeeper;
pub use evidence::{TechnicalEvidence, Finding};
pub use core::types::{ValidatorModule, TechnicalSeverity, Action, RiskLevel};
pub use validators::Validator;

pub const KERNEL_VERSION: &str = "2.3.2";
pub const PROJECT_VERSION: &str = "3.0";
pub const PROTOCOL_VERSION: u16 = 3;

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
        assert!(info.contains("BuildToValue v3.0"));
        assert!(info.contains("Kernel v2.3.2"));
    }
}