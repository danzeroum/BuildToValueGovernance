//! Durable backend trait + in-memory reference implementation.
//!
//! The trait allows future replacement with a persistent store
//! (RocksDB, PostgreSQL, etc.) without touching the API layer.
use crate::merkle::MerkleTree;
use std::sync::Mutex;

/// Durable backend for the Merkle tree state.
pub trait LogStore: Send + Sync {
    fn append(&self, leaf_hash: [u8; 32]) -> u64;
    fn root(&self) -> [u8; 32];
    fn size(&self) -> u64;
    fn leaf_at(&self, index: u64) -> Option<[u8; 32]>;
    fn proof(&self, index: u64) -> Option<Vec<([u8; 32], crate::merkle::Side)>>;
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
        self.tree.lock().expect("store lock poisoned").append(leaf_hash)
    }

    fn root(&self) -> [u8; 32] {
        self.tree.lock().expect("store lock poisoned").root()
    }

    fn size(&self) -> u64 {
        self.tree.lock().expect("store lock poisoned").size()
    }

    fn leaf_at(&self, index: u64) -> Option<[u8; 32]> {
        self.tree.lock().expect("store lock poisoned")
            .leaves.get(index as usize).copied()
    }

    fn proof(&self, index: u64) -> Option<Vec<([u8; 32], crate::merkle::Side)>> {
        self.tree.lock().expect("store lock poisoned").proof(index)
    }
}
