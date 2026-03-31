//! Append-only Merkle tree backed by SHA-256.
//!
//! Paper 2, Theorem 3.4: the append-only log Σ guarantees persistence
//! of every VerdictRecord via a publicly-verifiable Merkle root signed
//! by the Log Authority's Ed25519 key.
//!
//! Invariants:
//! - `append` is the ONLY mutating operation (no delete, no update)
//! - `root()` is deterministic given the same ordered leaf sequence
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
    /// Returns `None` if index is out of range.
    pub fn proof(&self, index: u64) -> Option<Vec<([u8; 32], Side)>> {
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
                let side = if idx % 2 == 0 { Side::Right } else { Side::Left };
                path.push((level[sibling], side));
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
            let mut next = Vec::with_capacity((current.len() + 1) / 2);
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

#[derive(Clone, Copy, Debug)]
pub enum Side { Left, Right }

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Standalone Merkle proof verifier.
/// Pure function — usable by btv-judicial via btv-types without importing btv-sigma.
pub fn verify_proof(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &[([u8; 32], Side)],
) -> bool {
    let mut current = *leaf_hash;
    for (sibling, side) in proof {
        current = match side {
            Side::Left => hash_pair(sibling, &current),
            Side::Right => hash_pair(&current, sibling),
        };
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
        assert_eq!(tree.root(), hash_pair(&a, &b));
    }

    #[test]
    fn proof_verifies_correctly() {
        let mut tree = MerkleTree::new();
        for i in 0u8..4 {
            tree.append([i; 32]);
        }
        let root = tree.root();
        for i in 0..4u64 {
            let proof = tree.proof(i).unwrap();
            assert!(verify_proof(&root, &tree.leaves[i as usize], &proof));
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
}
