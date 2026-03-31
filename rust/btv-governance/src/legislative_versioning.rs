//! Temporal Type Versioning — maintains the chain of legislative versions
//! `L = {L_0, ..., L_v}` and enforces monotonic progression.
//!
//! Paper 6, §3.1: "The legislative version L_v is a monotonically increasing
//! counter bound to each MandateToken."

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// A single entry in the immutable legislative chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegislativeVersion {
    /// Monotonically increasing version counter.
    pub version: u64,

    /// UTC timestamp when this version became active.
    pub activated_at: DateTime<Utc>,

    /// Human-readable summary of what changed in this version.
    pub change_summary: String,

    /// BLAKE3 hash of the MandateToken that activated this version.
    pub mandate_hash: [u8; 32],
}

/// The full immutable chain of legislative versions.
///
/// Acts as the canonical audit trail of constitutional evolution.
#[derive(Debug, Default)]
pub struct LegislativeChain {
    versions: Vec<LegislativeVersion>,
}

impl LegislativeChain {
    /// Create an empty chain.
    pub fn new() -> Self {
        Self { versions: vec![] }
    }

    /// Append a new version to the chain.
    ///
    /// Enforces monotonic progression: the new version must equal
    /// `last_version + 1`.
    pub fn append(
        &mut self,
        entry: LegislativeVersion,
    ) -> Result<(), crate::error::GovernanceError> {
        let expected = self
            .versions
            .last()
            .map_or(0, |v| v.version + 1);
        if entry.version != expected {
            return Err(crate::error::GovernanceError::VersionMismatch {
                expected,
                got: entry.version,
            });
        }
        self.versions.push(entry);
        Ok(())
    }

    /// Current (latest) version number.
    pub fn current_version(&self) -> u64 {
        self.versions.last().map_or(0, |v| v.version)
    }

    /// Immutable view of the chain.
    pub fn entries(&self) -> &[LegislativeVersion] {
        &self.versions
    }

    /// Find a version entry by its version number.
    pub fn find(&self, version: u64) -> Option<&LegislativeVersion> {
        self.versions.iter().find(|v| v.version == version)
    }
}
