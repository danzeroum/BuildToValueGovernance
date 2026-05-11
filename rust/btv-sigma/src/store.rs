//! Durable backend trait + in-memory reference implementation.
//!
//! The trait allows future replacement with a persistent store
//! (RocksDB, PostgreSQL, etc.) without touching the API layer.
//!
//! Phase 4: proof() returns Vec<[u8; 32]> (no Side) to match btv-types::MerkleProof.path.

use crate::merkle::MerkleTree;
use std::sync::Mutex;

/// Durable backend for the Merkle tree state.
pub trait LogStore: Send + Sync {
    fn append(&self, leaf_hash: [u8; 32]) -> u64;
    fn root(&self) -> [u8; 32];
    fn size(&self) -> u64;
    fn leaf_at(&self, index: u64) -> Option<[u8; 32]>;
    /// Returns sibling hashes only — compatible with btv-types::MerkleProof.path.
    /// Phase 4: removed Side enum (canonical ordering makes it unnecessary).
    fn proof(&self, index: u64) -> Option<Vec<[u8; 32]>>;
}

/// In-memory store — reference implementation for tests and development.
pub struct InMemoryStore {
    tree: Mutex<MerkleTree>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self { tree: Mutex::new(MerkleTree::new()) }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self { Self::new() }
}

impl LogStore for InMemoryStore {
    fn append(&self, leaf_hash: [u8; 32]) -> u64 {
        self.tree
            .lock()
            .unwrap_or_else(|e| panic!("BTV invariant: store lock poisoned: {e}"))
            .append(leaf_hash)
    }

    fn root(&self) -> [u8; 32] {
        self.tree
            .lock()
            .unwrap_or_else(|e| panic!("BTV invariant: store lock poisoned: {e}"))
            .root()
    }

    fn size(&self) -> u64 {
        self.tree
            .lock()
            .unwrap_or_else(|e| panic!("BTV invariant: store lock poisoned: {e}"))
            .size()
    }

    fn leaf_at(&self, index: u64) -> Option<[u8; 32]> {
        self.tree
            .lock()
            .unwrap_or_else(|e| panic!("BTV invariant: store lock poisoned: {e}"))
            .leaves
            .get(index as usize)
            .copied()
    }

    fn proof(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        self.tree
            .lock()
            .unwrap_or_else(|e| panic!("BTV invariant: store lock poisoned: {e}"))
            .proof(index)
    }
}
