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
//!   matching btv-types::verify_merkle_inclusion exactly
//!
//! Phase 3 BREAKING CHANGE: proofs are now `Vec<[u8; 32]>` (sibling hashes,
//! no Side info). Canonical ordering removes the need for side labels.
//! Existing callers of `Vec<([u8; 32], Side)>` must be updated.

use sha2::{Sha256, Digest};

pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    /// Levels stored bottom-up. Level 0 = leaves.
    nodes: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new(), nodes: Vec::new() }
    }

    /// Append a leaf. Returns the leaf index.
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
    ///
    /// Returns sibling hashes only — no side labels needed because canonical
    /// ordering (min/max) is symmetric. Compatible with btv-types::MerkleProof.
    pub fn proof(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        if index >= self.leaves.len() as u64 {
            return None;
        }
        let mut path = Vec::new();
        let mut idx = index as usize;
        let level_count = self.nodes.len();
        for level_idx in 0..level_count.saturating_sub(1) {
            let level = &self.nodes[level_idx];
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
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
/// Commutative: hash_pair(a,b) == hash_pair(b,a).
/// This is the SINGLE source of truth for parent-node computation and is
/// identical to the algorithm in btv-types::verify_merkle_inclusion.
pub fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if a <= b {
        hasher.update(a);
        hasher.update(b);
    } else {
        hasher.update(b);
        hasher.update(a);
    }
    hasher.finalize().into()
}

/// Verify a Merkle inclusion proof using canonical ordering.
///
/// Identical logic to btv-types::verify_merkle_inclusion — the Judiciary
/// uses the same algorithm so proofs generated here will always verify.
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
    fn two_leaves_root_is_hash_pair() {
        let mut tree = MerkleTree::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        tree.append(a);
        tree.append(b);
        // canonical: min(a,b) || max(a,b) — a < b so result is sha256(a||b)
        assert_eq!(tree.root(), hash_pair(&a, &b));
    }

    #[test]
    fn canonical_ordering_is_commutative() {
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        assert_eq!(hash_pair(&a, &b), hash_pair(&b, &a));
    }

    #[test]
    fn proof_verifies_locally() {
        let mut tree = MerkleTree::new();
        for i in 0u8..8 {
            tree.append([i; 32]);
        }
        let root = tree.root();
        for i in 0..8u64 {
            let proof = tree.proof(i).unwrap();
            assert!(
                verify_proof(&root, &tree.leaves[i as usize], &proof),
                "Local verification failed for leaf {i}"
            );
        }
    }

    #[test]
    fn proof_cross_verifies_with_btv_types() {
        // Critical test: btv-sigma proofs MUST verify with btv-types::verify_merkle_inclusion
        // so btv-judicial will accept them.
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
                "Cross-verification failed for leaf {i}: btv-judicial would reject this proof"
            );
        }
    }

    #[test]
    fn cross_verify_various_tree_sizes() {
        for size in 1u8..=20 {
            let mut tree = MerkleTree::new();
            for i in 0..size {
                tree.append([i; 32]);
            }
            let root = tree.root();
            for i in 0..size as u64 {
                let proof = tree.proof(i).unwrap();
                let btv_proof = btv_types::MerkleProof { path: proof, leaf_index: i };
                assert!(
                    btv_types::verify_merkle_inclusion(&root, &tree.leaves[i as usize], &btv_proof),
                    "Cross-verification failed: size={size}, leaf={i}"
                );
            }
        }
    }

    #[test]
    fn cross_verify_unsorted_leaves() {
        let mut tree = MerkleTree::new();
        let leaves: Vec<[u8; 32]> = (0u8..10).rev().map(|i| [i; 32]).collect();
        for &leaf in &leaves {
            tree.append(leaf);
        }
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i as u64).unwrap();
            let btv_proof = btv_types::MerkleProof { path: proof, leaf_index: i as u64 };
            assert!(
                btv_types::verify_merkle_inclusion(&root, leaf, &btv_proof),
                "Cross-verification failed for unsorted leaf {i}"
            );
        }
    }

    #[test]
    fn tampered_leaf_fails_verification() {
        let mut tree = MerkleTree::new();
        tree.append([1u8; 32]);
        tree.append([2u8; 32]);
        let root = tree.root();
        let proof = tree.proof(0).unwrap();
        let tampered = [0xFFu8; 32];
        assert!(!verify_proof(&root, &tampered, &proof));
    }

    #[test]
    fn empty_tree_returns_zero_root() {
        let tree = MerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
        assert_eq!(tree.size(), 0);
        assert!(tree.proof(0).is_none());
    }
}
