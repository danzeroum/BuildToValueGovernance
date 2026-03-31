//! Governance-specific error types.

use chrono::{DateTime, Utc};

/// All errors that can arise from btv-governance operations.
#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    /// The MandateToken has passed its expiry — system enters Interregnum.
    #[error("Mandate expired: version {version} expired at {expired_at}")]
    MandateExpired {
        version:    u64,
        expired_at: DateTime<Utc>,
    },

    /// No active mandate exists — cannot produce decisions.
    #[error("No active mandate — system is in Constitutional Interregnum")]
    NoMandate,

    /// Tripartite ratification proof is invalid.
    #[error("Invalid ratification: {0}")]
    InvalidRatification(String),

    /// Legislative version mismatch during amendment.
    #[error("Version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u64, got: u64 },

    /// Genesis mandate was already expired when supplied.
    #[error("Genesis mandate is already expired")]
    GenesisMandateExpired,

    /// Sunset policy exhausted all allowed renewals.
    #[error("Sunset policy exhausted: {policy_id} ({renewals}/{max} renewals)")]
    SunsetPolicyExhausted {
        policy_id: String,
        renewals:  u32,
        max:       u32,
    },

    /// Could not publish mandate/amendment to Transparency Log (Σ).
    #[error("Log publication failed: {0}")]
    LogPublicationFailed(String),

    /// Required configuration key is absent.
    #[error("Configuration missing: {0}")]
    ConfigurationMissing(String),
}
