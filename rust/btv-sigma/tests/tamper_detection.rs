//! Integration test: tampered Merkle entry must fail proof verification.
//!
//! Paper 2, Theorem 3.4: Merkle root binds all prior entries.
//! Any alteration changes the root and invalidates outstanding proofs.

#[test]
fn altered_root_invalidates_proof() {
    // Covered by btv-sigma::merkle::tests::tampered_leaf_fails_verification.
    // This file documents the requirement; exhaustive tests live in merkle.rs.
}
