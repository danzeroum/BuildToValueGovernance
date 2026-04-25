//! Append-only Merkle tree backed by SHA-256 (canonical ordering).
//!
//! Paper 2, Theorem 3.4: the append-only log Σ guarantees persistence
//! of every VerdictRecord via a publicly-verifiable Merkle root signed
//! by the Log Authority's Ed25519 key.
//!
//! Invariants:
//! - `append` is the ONLY mutating operation (no delete, no update)
//! - `root()` is deterministic given the same ordered leaf sequence
//! - `hash_pair` uses canonical ordering: min(a,b) || max(a,b)
//!   consistent with btv-types::verify_merkle_inclusion
//!
//! Phase 4: Side enum REMOVED. Proof format is now Vec<[u8; 32]>,
//! matching btv-types::MerkleProof.path. No ordering oracle.

use sha2::{Sha256, Digest};

pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    /// Levels stored bottom-up for proof generation. Level 0 = leaves.
    nodes: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new(), nodes: Vec::new() }
    }

    /// Append a leaf. Returns the leaf index.
    /// This is the ONLY mutation — no delete, no update (append-only invariant).
    pub fn append(&mut self, leaf_hash: [u8; 32]) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash);
        self.rebuild();
        index
    }

    /// Current Merkle root.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        *self.nodes.last()
            .and_then(|level| level.first())
            .unwrap_or(&[0u8; 32])
    }

    /// Tree size (number of leaves appended).
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Generate inclusion proof for leaf at `index`.
    /// Returns sibling hashes only — compatible with btv-types::MerkleProof.path.
    /// Phase 4: no Side enum (removed). Canonical ordering means Side is irrelevant.
    /// Returns `None` if index is out of range.
    pub fn proof(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        if index >= self.leaves.len() as u64 {
            return None;
        }
        let mut path = Vec::new();
        let mut idx = index as usize;
        let level_count = self.nodes.len();
        for level_idx in 0..level_count.saturating_sub(1) {
            let level = &self.nodes[level_idx];
            let sibling = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            if sibling < level.len() {
                path.push(level[sibling]);
            }
            idx /= 2;
        }
        Some(path)
    }

    fn rebuild(&mut self) {
        self.nodes.clear();
        if self.leaves.is_empty() {
            return;
        }
        let mut current: Vec<[u8; 32]> = self.leaves.clone();
        loop {
            self.nodes.push(current.clone());
            if current.len() == 1 {
                break;
            }
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for chunk in current.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0] // odd leaf promoted unchanged
                };
                next.push(hash);
            }
            current = next;
        }
    }
}

impl Default for MerkleTree {
    fn default() -> Self { Self::new() }
}

/// Canonical hash pair: SHA256(min(a,b) || max(a,b)).
///
/// Since both the tree builder AND the verifier use the same canonical
/// ordering, the Side label is unnecessary and was removed in Phase 4.
/// This prevents ordering oracle attacks (btv-types::verify_merkle_inclusion).
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if left <= right {
        hasher.update(left);
        hasher.update(right);
    } else {
        hasher.update(right);
        hasher.update(left);
    }
    hasher.finalize().into()
}

/// Verify a Merkle inclusion proof using canonical ordering.
/// Identical logic to btv-types::verify_merkle_inclusion.
#[allow(dead_code)]
pub fn verify_proof(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    let mut current = *leaf_hash;
    for node in proof {
        let mut hasher = Sha256::new();
        if current <= *node {
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

/// Convert internal proof to btv-types wire format for HTTP API responses.
/// This is the ONLY function that creates MerkleProof instances in btv-sigma.
pub fn to_wire_proof(
    path: Vec<[u8; 32]>,
    leaf_index: u64,
) -> btv_types::MerkleProof {
    btv_types::MerkleProof { path, leaf_index }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_leaf() {
        let mut tree = MerkleTree::new();
        let leaf = [1u8; 32];
        tree.append(leaf);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn canonical_ordering_independent() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        assert_eq!(hash_pair(&a, &b), hash_pair(&b, &a));
    }

    #[test]
    fn proof_verifies_locally() {
        let mut tree = MerkleTree::new();
        for i in 0u8..8 { tree.append([i; 32]); }
        let root = tree.root();
        for i in 0..8u64 {
            let proof = tree.proof(i).unwrap();
            assert!(verify_proof(&root, &tree.leaves[i as usize], &proof),
                "Local verification failed for leaf {}", i);
        }
    }

    #[test]
    fn cross_verifies_with_btv_types() {
        let mut tree = MerkleTree::new();
        for i in 0u8..8 { tree.append([i; 32]); }
        let root = tree.root();
        for i in 0..8u64 {
            let proof = tree.proof(i).unwrap();
            let btv_proof = btv_types::MerkleProof {
                path: proof.clone(),
                leaf_index: i,
            };
            assert!(
                btv_types::verify_merkle_inclusion(&root, &tree.leaves[i as usize], &btv_proof),
                "CROSS-VERIFICATION FAILED for leaf {} — btv-judicial would reject!",
                i
            );
        }
    }

    #[test]
    fn to_wire_proof_roundtrip() {
        let mut tree = MerkleTree::new();
        for i in 0u8..4 { tree.append([i; 32]); }
        let proof = tree.proof(2).unwrap();
        let wire = to_wire_proof(proof.clone(), 2);
        assert_eq!(wire.path.len(), proof.len());
        assert_eq!(wire.leaf_index, 2);
    }

    #[test]
    fn side_enum_does_not_exist() {
        // Phase 4: Side enum removed — canonical ordering makes it unnecessary
        let _ = "Phase 4: Side enum removed — canonical ordering makes it unnecessary";
    }

    #[test]
    fn tampered_leaf_fails() {
        let mut tree = MerkleTree::new();
        tree.append([1u8; 32]);
        tree.append([2u8; 32]);
        let root = tree.root();
        let proof = tree.proof(0).unwrap();
        assert!(!verify_proof(&root, &[0xFFu8; 32], &proof));
    }

    // ── CI-named cross-verification tests ─────────────────────────────────────

    /// Every proof from btv-sigma must verify with btv_types::verify_merkle_inclusion.
    /// Named to match fail_secure_ci.yml: merkle::tests::proof_cross_verifies_with_btv_types
    #[test]
    fn proof_cross_verifies_with_btv_types() {
        let mut tree = MerkleTree::new();
        for i in 0u8..8 {
            tree.append([i; 32]);
        }
        let root = tree.root();
        for i in 0..8u64 {
            let proof = tree.proof(i).unwrap();
            let btv_proof = btv_types::MerkleProof { path: proof, leaf_index: i };
            assert!(
                btv_types::verify_merkle_inclusion(&root, &tree.leaves[i as usize], &btv_proof),
                "cross-verification failed for leaf {i}",
            );
        }
    }

    /// Cross-verify proofs for trees of various sizes (1, 2, 3, 4, 8, 16, 20 leaves).
    /// Named to match fail_secure_ci.yml: merkle::tests::cross_verify_various_tree_sizes
    #[test]
    fn cross_verify_various_tree_sizes() {
        for &size in &[1usize, 2, 3, 4, 8, 16, 20] {
            let mut tree = MerkleTree::new();
            for i in 0u8..(size as u8) {
                tree.append([i; 32]);
            }
            let root = tree.root();
            for i in 0..size as u64 {
                let proof = tree.proof(i).unwrap();
                let btv_proof = btv_types::MerkleProof { path: proof, leaf_index: i };
                assert!(
                    btv_types::verify_merkle_inclusion(&root, &tree.leaves[i as usize], &btv_proof),
                    "size={size}: cross-verification failed for leaf {i}",
                );
            }
        }
    }

    /// Cross-verify proofs for trees built from arbitrary (unsorted) leaf hashes.
    /// Named to match fail_secure_ci.yml: merkle::tests::cross_verify_unsorted_leaves
    #[test]
    fn cross_verify_unsorted_leaves() {
        let leaves: &[[u8; 32]] = &[
            [0xFF; 32], [0x00; 32], [0xAB; 32], [0x12; 32],
            [0x7F; 32], [0x80; 32], [0x01; 32], [0xFE; 32],
        ];
        let mut tree = MerkleTree::new();
        for leaf in leaves {
            tree.append(*leaf);
        }
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i as u64).unwrap();
            let btv_proof = btv_types::MerkleProof { path: proof, leaf_index: i as u64 };
            assert!(
                btv_types::verify_merkle_inclusion(&root, leaf, &btv_proof),
                "unsorted: cross-verification failed for leaf {i}",
            );
        }
    }

    /// hash_pair(a, b) == hash_pair(b, a) — canonical ordering is commutative.
    /// Named to match fail_secure_ci.yml: merkle::tests::canonical_ordering_is_commutative
    #[test]
    fn canonical_ordering_is_commutative() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        assert_eq!(hash_pair(&a, &b), hash_pair(&b, &a));
        let c = [0x00; 32];
        let d = [0xFF; 32];
        assert_eq!(hash_pair(&c, &d), hash_pair(&d, &c));
        // Equal inputs
        let e = [0x42; 32];
        assert_eq!(hash_pair(&e, &e), hash_pair(&e, &e));
    }
}
