//! `ComplianceToken` — linear resource encoding a validated regulatory obligation.
//!
//! External crates cannot construct this directly (`new_internal` is `pub(crate)`).
//! The only public construction path is `ComplianceAuthority::issue()`.

/// A linear resource encoding jurisdiction, policy version, and contestability window.
///
/// Cannot be cloned or silently dropped (same Axiom 4.4 constraints as `EvidenceToken`).
#[must_use = "ComplianceToken must be consumed by Verdict::new"]
pub struct ComplianceToken {
    jurisdiction: String,
    policy_version: String,
    contestability_hours: u32,
}

impl ComplianceToken {
    /// Internal-only constructor. External code must use `ComplianceAuthority::issue()`.
    pub(crate) fn new_internal(
        jurisdiction: String,
        policy_version: String,
        contestability_hours: u32,
    ) -> Self {
        Self { jurisdiction, policy_version, contestability_hours }
    }

    pub(crate) fn jurisdiction(&self) -> &str {
        &self.jurisdiction
    }

    pub(crate) fn policy_version(&self) -> &str {
        &self.policy_version
    }

    #[allow(dead_code)] // Used in Phase 3 (btv-executive) for contestability window enforcement
    pub(crate) fn contestability_hours(&self) -> u32 {
        self.contestability_hours
    }
}

// Explicitly NOT implementing Clone or Copy.
