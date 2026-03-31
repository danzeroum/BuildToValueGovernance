//! `ComplianceAuthority` — the sole public path to a `ComplianceToken`.
//!
//! Paper 1, §6 (proposed extension): closes the public constructor gap.
//! Before this type existed, anyone could call `ComplianceToken::new(...)` directly.
//! Now `new_internal` is `pub(crate)` and all external callers must go through
//! `ComplianceAuthority::issue()`, which validates against a pluggable registry.

use crate::compliance_token::ComplianceToken;

/// Pluggable backend for jurisdiction + policy validation.
pub trait ComplianceRegistry: Send + Sync {
    /// Returns the contestability window in hours, or an error if invalid.
    fn validate(
        &self,
        jurisdiction: &str,
        policy_version: &str,
    ) -> Result<u32, ComplianceError>;
}

/// The SOLE public path to a `ComplianceToken`.
///
/// Validates jurisdiction + policy version against a registry before issuing.
/// This is the factory that enforces the "compliance must be earned, not assumed"
/// invariant from Paper 1 §6.
pub struct ComplianceAuthority {
    registry: Box<dyn ComplianceRegistry>,
}

impl ComplianceAuthority {
    pub fn new(registry: Box<dyn ComplianceRegistry>) -> Self {
        Self { registry }
    }

    /// Issue a `ComplianceToken` after validating against the registry.
    ///
    /// This is the only public way to obtain a `ComplianceToken`.
    pub fn issue(
        &self,
        jurisdiction: &str,
        policy_version: &str,
    ) -> Result<ComplianceToken, ComplianceError> {
        let contestability_hours = self.registry.validate(jurisdiction, policy_version)?;
        Ok(ComplianceToken::new_internal(
            jurisdiction.to_string(),
            policy_version.to_string(),
            contestability_hours,
        ))
    }
}

/// Errors from the compliance registry.
#[derive(Debug, thiserror::Error)]
pub enum ComplianceError {
    #[error("Unknown jurisdiction: {0}")]
    UnknownJurisdiction(String),
    #[error("Invalid policy version for jurisdiction {0}: {1}")]
    InvalidPolicy(String, String),
    #[error("Compliance registry unavailable")]
    Unavailable,
}
