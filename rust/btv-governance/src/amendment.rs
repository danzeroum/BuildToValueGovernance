//! Amendment types for the Living Constitution.
//!
//! Paper 6, Definitions 3.1 and 3.2:
//! - Ordinary amendments modify `L \ L*` — require only Legislative signature.
//! - Constitutional amendments modify `L*` (Stone Clauses) — require Tripartite
//!   Ratification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::mandate::AmendmentId;

// ── Amendment ────────────────────────────────────────────────────────────────

/// A proposed or ratified amendment to the constitutional framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Amendment {
    /// Unique identifier (monotonically increasing for numbered amendments).
    pub id: AmendmentId,

    /// Type and payload of the amendment.
    pub kind: AmendmentKind,

    /// Human-readable description for audit trail.
    pub description: String,

    /// Legislative version this amendment targets.
    pub target_version: u64,

    /// The version **before** this amendment is applied.
    pub previous_version: u64,

    /// UTC timestamp of proposal.
    pub proposed_at: DateTime<Utc>,

    /// Anti-replay nonce (unique per proposal).
    pub nonce: [u8; 32],
}

// ── AmendmentKind ────────────────────────────────────────────────────────────

/// Two kinds of amendment — each with different ratification requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AmendmentKind {
    /// Ordinary: modifies `L \ L*`.
    /// Requires ONLY σ_L (Legislative signature).
    /// Examples: threshold adjustments, new sector policies.
    PolicyUpdate(PolicyDelta),

    /// Constitutional: modifies `L*` (Stone Clauses).
    /// Requires Tripartite Ratification (σ_L ∧ σ_J ∧ σ_Erep).
    /// Examples: changing Evidence Binding invariant, ZK audit access.
    ConstitutionalAmendment(ConstitutionalDelta),
}

/// Delta payload for ordinary policy changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDelta {
    pub changed_files:       Vec<String>,
    pub change_description:  String,
}

/// Delta payload for constitutional changes — must reference a Stone Clause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionalDelta {
    /// Identifier of the Stone Clause being modified.
    pub stone_clause_id: String,
    /// Description of the modification.
    pub modification: String,
}
