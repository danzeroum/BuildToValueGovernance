//! Stone Clauses — the immutable constitutional invariants of the Algorithmic
//! Republic.
//!
//! Paper 6, Definition 3.2:
//! "Stone Clauses are the subset L* ⊂ L that require Tripartite Ratification
//!  for modification. A coalition of any two branches is insufficient."
//!
//! SC-001..SC-006 map one-to-one to invariants proven in Papers 1–6.

use serde::{Deserialize, Serialize};

use crate::amendment::Amendment;

// ── StoneClause ──────────────────────────────────────────────────────────────

/// A constitutional invariant that can only be changed by Tripartite
/// Ratification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoneClause {
    /// Short identifier, e.g. "SC-001".
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Description of the invariant protected by this clause.
    pub description: String,
    /// Formal invariant expression.
    pub invariant: String,
    /// Paper that establishes this invariant.
    pub paper_reference: String,
    /// Legislative version when this clause was established.
    pub established_at_version: u64,
}

// ── Canonical clauses ─────────────────────────────────────────────────────────

/// Returns the canonical set of Stone Clauses for BTV v3.0.
///
/// These six clauses cover all invariants established in Papers 1–6.
/// They CANNOT be modified by a two-branch coalition (Paper 6, §3.2).
pub fn canonical_stone_clauses() -> Vec<StoneClause> {
    vec![
        StoneClause {
            id: "SC-001".into(),
            title: "Evidence Binding Invariant".into(),
            description: "Every Verdict must consume an EvidenceToken (BLAKE3) and a \
                           ComplianceToken (HMAC). Silent decisions are type errors."
                .into(),
            invariant:          "V ⊸ (E ⊗ C)".into(),
            paper_reference:    "Paper 1, Theorem 4.6".into(),
            established_at_version: 0,
        },
        StoneClause {
            id: "SC-002".into(),
            title: "Delivery Persistence Invariant".into(),
            description: "Every Verdict must be sealed with an InclusionReceipt from the \
                           Transparency Log. Ephemeral verdicts are type errors."
                .into(),
            invariant:          "DeliveryToken ⊸ (V ⊗ R)".into(),
            paper_reference:    "Paper 2, Theorem 3.4".into(),
            established_at_version: 0,
        },
        StoneClause {
            id: "SC-003".into(),
            title: "Power Separation Invariant".into(),
            description: "The three branches have disjoint capabilities. No branch can \
                           perform the duties of another."
                .into(),
            invariant:          "P_L ∩ P_E ∩ P_J = ∅".into(),
            paper_reference:    "Paper 5, Corollary 3.6".into(),
            established_at_version: 0,
        },
        StoneClause {
            id: "SC-004".into(),
            title: "Redaction Statistical Integrity".into(),
            description: "No redaction may distort the approval rate of any protected \
                           group by more than ε. Proven via ZK-SNARK."
                .into(),
            invariant:          "∀g: |q_g^before - q_g^after| ≤ ε".into(),
            paper_reference:    "Paper 3, Circuit C".into(),
            established_at_version: 0,
        },
        StoneClause {
            id: "SC-005".into(),
            title: "Constitutional Mandate Expiry".into(),
            description: "The system enters Constitutional Interregnum when the \
                           MandateToken expires. No new decisions are produced."
                .into(),
            invariant:          "Verdict::new fails if t_now > m.t_exp".into(),
            paper_reference:    "Paper 6, Theorem 3.6".into(),
            established_at_version: 0,
        },
        StoneClause {
            id: "SC-006".into(),
            title: "Attested Demographics".into(),
            description: "Demographic attributes used in statistical consistency checks \
                           must be attested by an external source (identity provider, \
                           civil registry)."
                .into(),
            invariant: "∀entry: Verify(pk_src, sig_src, group_label || subject_id)".into(),
            paper_reference: "Paper 3, §7.1 + Paper 6, §4.3".into(),
            established_at_version: 0,
        },
    ]
}

// ── Guard ────────────────────────────────────────────────────────────────────

/// Returns `true` if `amendment` targets a Stone Clause.
///
/// A `PolicyUpdate` never touches Stone Clauses.
/// A `ConstitutionalAmendment` touches a Stone Clause iff its
/// `stone_clause_id` matches one of the canonical IDs.
pub fn is_stone_clause_modification(amendment: &Amendment) -> bool {
    use crate::amendment::AmendmentKind;
    match &amendment.kind {
        AmendmentKind::ConstitutionalAmendment(delta) => {
            canonical_stone_clauses()
                .iter()
                .any(|c| c.id == delta.stone_clause_id)
        }
        AmendmentKind::PolicyUpdate(_) => false,
    }
}
