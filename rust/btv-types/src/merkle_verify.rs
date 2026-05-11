//! Standalone Merkle inclusion verifier.
//!
//! Pure function — btv-judicial imports ONLY btv-types to verify proofs,
//! never btv-sigma or btv-core (Criterion 10, Phase 2).
//!
//! v2.3.1: Added side-based proof API (`ProofSide`, `verify_side_proof`) to match
//! btv-sigma's tree construction convention. The legacy `verify_merkle_inclusion`
//! function (canonical / min-first ordering) is preserved for backward compat.
//!
//! btv-sigma's tree uses side-based ordering:
//!   ProofSide::Left  → hash_pair(sibling, current)  [sibling is on the left]
//!   ProofSide::Right → hash_pair(current, sibling)  [current is on the left]
//!
//! The canonical verifier uses min-first ordering which is NOT compatible with
//! btv-sigma proofs. Use `verify_side_proof` for proofs from btv-sigma.
use sha2::{Sha256, Digest};

/// Side of the sibling node in a Merkle proof path step.
/// Matches btv-sigma's `Side` enum in its tree construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSide {
    /// Sibling is to the left: hash_pair(sibling, current)
    Left,
    /// Sibling is to the right: hash_pair(current, sibling)
    Right,
}

/// Verify a Merkle inclusion proof using btv-sigma's side-based format.
///
/// Each entry in `proof` is `(sibling_hash, side)` where `side` indicates
/// which side of the pair the sibling occupies. This matches btv-sigma's
/// `verify_proof` algorithm exactly.
pub fn verify_side_proof(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &[([u8; 32], ProofSide)],
) -> bool {
    let mut current = *leaf_hash;
    for (sibling, side) in proof {
        let mut hasher = Sha256::new();
        match side {
            ProofSide::Left  => { hasher.update(sibling); hasher.update(current); }
            ProofSide::Right => { hasher.update(current); hasher.update(sibling); }
        }
        current = hasher.finalize().into();
    }
    &current == root
}

/// Verify a Merkle inclusion proof using canonical (min-first) ordering.
///
/// Canonical ordering: `min(current, sibling) || max(current, sibling)`.
/// Since Phase 4, btv-sigma also uses this canonical ordering, so proofs
/// from btv-sigma verify correctly with this function.
/// `verify_side_proof` is kept for side-labelled proof formats.
pub fn verify_merkle_inclusion(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &crate::MerkleProof,
) -> bool {
    let mut current = *leaf_hash;
    for node in &proof.path {
        let mut hasher = Sha256::new();
        if &current <= node {
            hasher.update(current);
            hasher.update(node);
        } else {
            hasher.update(node);
            hasher.update(current);
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
    fn canonical_empty_proof_leaf_equals_root() {
        let leaf = [0x42u8; 32];
        let proof = MerkleProof { path: vec![], leaf_index: 0 };
        assert!(verify_merkle_inclusion(&leaf, &leaf, &proof));
    }

    #[test]
    fn canonical_wrong_root_fails() {
        let leaf = [0x01u8; 32];
        let wrong_root = [0xFFu8; 32];
        let proof = MerkleProof { path: vec![], leaf_index: 0 };
        assert!(!verify_merkle_inclusion(&wrong_root, &leaf, &proof));
    }

    #[test]
    fn side_proof_empty_leaf_equals_root() {
        let leaf = [0x42u8; 32];
        assert!(verify_side_proof(&leaf, &leaf, &[]));
    }

    #[test]
    fn side_proof_single_step_left() {
        let leaf = [0x01u8; 32];
        let sibling = [0x02u8; 32];
        // ProofSide::Left → hash(sibling || leaf)
        let expected_root: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(sibling);
            h.update(leaf);
            h.finalize().into()
        };
        let proof = [(sibling, ProofSide::Left)];
        assert!(verify_side_proof(&expected_root, &leaf, &proof));
    }

    #[test]
    fn side_proof_single_step_right() {
        let leaf = [0x01u8; 32];
        let sibling = [0x02u8; 32];
        // ProofSide::Right → hash(leaf || sibling)
        let expected_root: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(leaf);
            h.update(sibling);
            h.finalize().into()
        };
        let proof = [(sibling, ProofSide::Right)];
        assert!(verify_side_proof(&expected_root, &leaf, &proof));
    }

    #[test]
    fn side_proof_wrong_root_fails() {
        let leaf = [0x01u8; 32];
        let sibling = [0x02u8; 32];
        let wrong_root = [0xFFu8; 32];
        let proof = [(sibling, ProofSide::Left)];
        assert!(!verify_side_proof(&wrong_root, &leaf, &proof));
    }
}
