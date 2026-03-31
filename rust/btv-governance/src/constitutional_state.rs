//! ConstitutionalState — tracks the active MandateToken and detects
//! Constitutional Interregnum.
//!
//! Paper 6, §3.4: "If no live mandate exists, the system enters
//! Constitutional Interregnum — no new Verdicts can be produced."

use chrono::{DateTime, Utc};

use crate::{
    amendment::Amendment,
    error::GovernanceError,
    mandate::MandateToken,
};

// ── SystemState ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemState {
    Active {
        version:    u64,
        expires_at: DateTime<Utc>,
    },
    Interregnum {
        since:        DateTime<Utc>,
        last_version: u64,
    },
}

// ── ConstitutionalState ───────────────────────────────────────────────────────

/// Owns the active `MandateToken` and maintains an immutable audit trail.
///
/// Thread-safety: wrap in `Arc<Mutex<ConstitutionalState>>` for concurrent use.
#[derive(Debug)]
pub struct ConstitutionalState {
    current_mandate: Option<MandateToken>,
    mandate_history: Vec<MandateToken>,
    pub current_version: u64,
}

impl ConstitutionalState {
    /// Bootstrap the constitutional system with a genesis mandate.
    pub fn genesis(initial_mandate: MandateToken) -> Result<Self, GovernanceError> {
        if !initial_mandate.is_live() {
            return Err(GovernanceError::GenesisMandateExpired);
        }
        if !initial_mandate.verify_ratification() {
            return Err(GovernanceError::InvalidRatification(
                "Genesis mandate has invalid ratification proof".into(),
            ));
        }
        Ok(Self {
            current_version:  initial_mandate.version(),
            current_mandate:  Some(initial_mandate),
            mandate_history:  vec![],
        })
    }

    pub fn state(&self) -> SystemState {
        match &self.current_mandate {
            Some(m) if m.is_live() => SystemState::Active {
                version:    m.version(),
                expires_at: m.expiry(),
            },
            Some(m) => SystemState::Interregnum {
                since:        m.expiry(),
                last_version: m.version(),
            },
            None => SystemState::Interregnum {
                since:        Utc::now(),
                last_version: self.current_version,
            },
        }
    }

    pub fn active_mandate(&self) -> Result<&MandateToken, GovernanceError> {
        match &self.current_mandate {
            Some(m) if m.is_live() => Ok(m),
            Some(m) => Err(GovernanceError::MandateExpired {
                version:    self.current_version,
                expired_at: m.expiry(),
            }),
            None => Err(GovernanceError::NoMandate),
        }
    }

    pub fn renew(&mut self, new_mandate: MandateToken) -> Result<(), GovernanceError> {
        if new_mandate.version() != self.current_version {
            return Err(GovernanceError::VersionMismatch {
                expected: self.current_version,
                got:      new_mandate.version(),
            });
        }
        if !new_mandate.is_live() {
            return Err(GovernanceError::MandateExpired {
                version:    new_mandate.version(),
                expired_at: new_mandate.expiry(),
            });
        }
        if !new_mandate.verify_ratification() {
            return Err(GovernanceError::InvalidRatification(
                "Renewal mandate has invalid ratification".into(),
            ));
        }
        if let Some(old) = self.current_mandate.take() {
            self.mandate_history.push(old);
        }
        self.current_mandate = Some(new_mandate);
        Ok(())
    }

    pub fn apply_amendment(
        &mut self,
        amendment: Amendment,
        new_mandate: MandateToken,
    ) -> Result<(), GovernanceError> {
        if new_mandate.version() != amendment.target_version {
            return Err(GovernanceError::VersionMismatch {
                expected: amendment.target_version,
                got:      new_mandate.version(),
            });
        }
        if new_mandate.version() != self.current_version + 1 {
            return Err(GovernanceError::VersionMismatch {
                expected: self.current_version + 1,
                got:      new_mandate.version(),
            });
        }
        if !new_mandate.verify_ratification() {
            return Err(GovernanceError::InvalidRatification(
                "Amendment mandate has invalid ratification proof".into(),
            ));
        }
        if let Some(old) = self.current_mandate.take() {
            self.mandate_history.push(old);
        }
        self.current_mandate  = Some(new_mandate);
        self.current_version  = amendment.target_version;
        Ok(())
    }

    pub fn mandate_count(&self) -> usize {
        self.mandate_history.len() + self.current_mandate.as_ref().map_or(0, |_| 1)
    }

    pub fn history(&self) -> &[MandateToken] {
        &self.mandate_history
    }
}
