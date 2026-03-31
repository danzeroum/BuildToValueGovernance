//! Standalone Merkle inclusion verifier.
//!
//! Pure function — btv-judicial imports ONLY btv-types to verify proofs,
//! never btv-sigma or btv-core (Criterion 10, Phase 2).
//!
//! Uses SHA-256 with canonical ordering (smaller hash first) consistent
//! with btv-sigma's `hash_pair` implementation.
use sha2::{Sha256, Digest};

/// Verify a Merkle inclusion proof from btv-sigma.
///
/// `proof.path` contains SHA-256 sibling hashes from leaf to root.
/// Canonical ordering: `min(current, sibling) || max(current, sibling)`
/// ensures the verifier and the tree agree without transmitting side information.
pub fn verify_merkle_inclusion(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &crate::MerkleProof,
) -> bool {
    let mut current = *leaf_hash;
    for node in &proof.path {
        let mut hasher = Sha256::new();
        // Canonical ordering: smaller hash first prevents ordering oracle attacks.
        if &current <= node {
            hasher.update(&current);
            hasher.update(node);
        } else {
            hasher.update(node);
            hasher.update(&current);
        }
        current = hasher.finalize().into();
    }
    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MerkleProof;

    #[test]
    fn empty_proof_leaf_equals_root() {
        let leaf = [0x42u8; 32];
        let proof = MerkleProof { path: vec![], leaf_index: 0 };
        assert!(verify_merkle_inclusion(&leaf, &leaf, &proof));
    }

    #[test]
    fn wrong_root_fails() {
        let leaf = [0x01u8; 32];
        let wrong_root = [0xFFu8; 32];
        let proof = MerkleProof { path: vec![], leaf_index: 0 };
        assert!(!verify_merkle_inclusion(&wrong_root, &leaf, &proof));
    }
}
