//! Sunset Clauses — ordinary policies that expire automatically unless renewed.
//!
//! Paper 6, §3.3:
//! "Sunset Clauses are encoded as temporal bounds on MandateToken validity —
//!  when the token expires the policy can no longer justify decisions."

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::GovernanceError;

/// A policy with an automatic sunset — expires unless renewed within its
/// validity window.
///
/// `max_renewals` creates a hard upper bound: after exhausting all renewals
/// the policy permanently expires and must be re-enacted via a new amendment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SunsetPolicy {
    /// Unique policy identifier (e.g. "POLICY-2026-003").
    pub policy_id: String,

    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,

    /// UTC expiry — after this instant `is_active()` returns `false`.
    pub sunset_at: DateTime<Utc>,

    /// Maximum number of renewals before permanent expiration.
    pub max_renewals: u32,

    /// Number of renewals performed so far.
    pub renewal_count: u32,

    /// Branch or role that authorised this policy.
    pub authorized_by: String,
}

impl SunsetPolicy {
    /// Construct a new policy valid for `duration` from now.
    pub fn new(
        policy_id:    String,
        duration:     Duration,
        max_renewals: u32,
        authorized_by: String,
    ) -> Self {
        let created_at = Utc::now();
        Self {
            policy_id,
            created_at,
            sunset_at: created_at + duration,
            max_renewals,
            renewal_count: 0,
            authorized_by,
        }
    }

    /// Returns `true` if the policy is currently active.
    #[inline]
    pub fn is_active(&self) -> bool {
        Utc::now() < self.sunset_at
    }

    /// Extend the policy's sunset by `extension`.
    ///
    /// Fails with `SunsetPolicyExhausted` when `renewal_count >= max_renewals`.
    pub fn renew(&mut self, extension: Duration) -> Result<(), GovernanceError> {
        if self.renewal_count >= self.max_renewals {
            return Err(GovernanceError::SunsetPolicyExhausted {
                policy_id: self.policy_id.clone(),
                renewals:  self.renewal_count,
                max:       self.max_renewals,
            });
        }
        self.sunset_at     = Utc::now() + extension;
        self.renewal_count += 1;
        Ok(())
    }

    /// Wall-clock time remaining before sunset.
    pub fn time_remaining(&self) -> Duration {
        let now = Utc::now();
        if now >= self.sunset_at {
            return Duration::zero();
        }
        self.sunset_at - now
    }
}
