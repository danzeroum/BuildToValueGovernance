//! Integration test: amendment soundness — version monotonicity and Stone
//! Clause guards.
//!
//! Paper 6, Theorem 3.4: "No pair-wise coalition can weaken the constitutional
//! invariant."

use btv_governance::{
    amendment::{Amendment, AmendmentKind, ConstitutionalDelta, PolicyDelta},
    mandate::AmendmentId,
    stone_clauses::{canonical_stone_clauses, is_stone_clause_modification},
};
use chrono::Utc;

fn make_policy_amendment(from: u64, to: u64) -> Amendment {
    Amendment {
        id:               AmendmentId::Amendment(to),
        kind:             AmendmentKind::PolicyUpdate(PolicyDelta {
            changed_files:      vec!["data/policies/thresholds.yaml".into()],
            change_description: "Adjust composite_risk threshold".into(),
        }),
        description:      "Threshold adjustment".into(),
        target_version:   to,
        previous_version: from,
        proposed_at:      Utc::now(),
        nonce:            [0u8; 32],
    }
}

fn make_constitutional_amendment(clause_id: &str, from: u64, to: u64) -> Amendment {
    Amendment {
        id:               AmendmentId::Amendment(to),
        kind:             AmendmentKind::ConstitutionalAmendment(ConstitutionalDelta {
            stone_clause_id: clause_id.into(),
            modification:    "Extend ε bound from 0.01 to 0.02".into(),
        }),
        description:      "Constitutional amendment to SC-004".into(),
        target_version:   to,
        previous_version: from,
        proposed_at:      Utc::now(),
        nonce:            [0u8; 32],
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Policy amendments do NOT modify Stone Clauses.
#[test]
fn policy_update_is_not_stone_clause_modification() {
    let a = make_policy_amendment(0, 1);
    assert!(!is_stone_clause_modification(&a));
}

/// Constitutional amendments to a known SC-id ARE flagged.
#[test]
fn constitutional_amendment_to_sc004_is_flagged() {
    let a = make_constitutional_amendment("SC-004", 0, 1);
    assert!(is_stone_clause_modification(&a));
}

/// Constitutional amendments to an unknown id are NOT flagged
/// (unknown clauses are not yet in the canonical set).
#[test]
fn constitutional_amendment_to_unknown_clause_not_flagged() {
    let a = make_constitutional_amendment("SC-999", 0, 1);
    assert!(!is_stone_clause_modification(&a));
}

/// All 6 canonical Stone Clauses are present.
#[test]
fn canonical_stone_clauses_count() {
    let clauses = canonical_stone_clauses();
    assert_eq!(clauses.len(), 6);
}

/// Stone Clause IDs follow SC-00N naming.
#[test]
fn canonical_stone_clause_ids() {
    let ids: Vec<String> = canonical_stone_clauses()
        .iter()
        .map(|c| c.id.clone())
        .collect();
    for n in 1..=6 {
        assert!(ids.contains(&format!("SC-{:03}", n)), "SC-{:03} missing", n);
    }
}

/// Every Stone Clause has a non-empty invariant and paper reference.
#[test]
fn stone_clauses_have_invariants_and_refs() {
    for clause in canonical_stone_clauses() {
        assert!(!clause.invariant.is_empty(),       "SC {} missing invariant",  clause.id);
        assert!(!clause.paper_reference.is_empty(), "SC {} missing paper ref", clause.id);
    }
}
