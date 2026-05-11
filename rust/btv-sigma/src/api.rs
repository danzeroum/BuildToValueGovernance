//! HTTP API for btv-sigma.
//!
//! Endpoints:
//! - POST /append          — append a verdict hash, get signed receipt
//! - GET  /root            — current Merkle root + tree size
//! - GET  /proof/{index}   — Merkle inclusion proof (btv-types compatible)
//!
//! Phase 4: proof response changed from Vec<([u8;32], "left"|"right")>
//! to Vec<[u8; 32]> (sibling hashes only). Canonical ordering means
//! the verifier doesn't need Side labels — min/max determines parent.

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{signer::LogSigner, store::LogStore};

pub struct AppState {
    pub store: Arc<dyn LogStore>,
    pub signer: LogSigner,
}

// ── POST /append ───────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AppendRequest {
    pub verdict_hash: [u8; 32],
}

#[derive(Serialize)]
pub struct AppendResponse {
    pub index: u64,
    pub root: [u8; 32],
    #[serde(with = "btv_types::serde_bytes_64_pub")]
    pub signature: [u8; 64],
    pub timestamp: u64,
}

pub async fn append(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AppendRequest>,
) -> Json<AppendResponse> {
    let index = state.store.append(req.verdict_hash);
    let root = state.store.root();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Sign: index(8) || root(32) || verdict_hash(32) || timestamp(8) = 80 bytes
    let mut message = Vec::with_capacity(80);
    message.extend_from_slice(&index.to_le_bytes());
    message.extend_from_slice(&root);
    message.extend_from_slice(&req.verdict_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let sig = state.signer.sign(&message);

    Json(AppendResponse {
        index,
        root,
        signature: sig.to_bytes(),
        timestamp,
    })
}

// ── GET /root ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RootResponse {
    pub root: [u8; 32],
    pub tree_size: u64,
}

pub async fn get_root(
    State(state): State<Arc<AppState>>,
) -> Json<RootResponse> {
    Json(RootResponse {
        root: state.store.root(),
        tree_size: state.store.size(),
    })
}

// ── GET /proof/{index} ────────────────────────────────────────────────────────────────────────

/// Proof response — btv-types compatible.
///
/// Phase 4: `proof` is now `Vec<[u8; 32]>` (sibling hashes only).
/// The verifier (btv-types::verify_merkle_inclusion) uses canonical
/// ordering `min(current, sibling) || max(current, sibling)`, so
/// Side labels ("left"/"right") are unnecessary and were removed.
///
/// `wire_proof` is the complete `MerkleProof` struct for direct
/// consumption by btv-judicial without any transformation.
#[derive(Serialize)]
pub struct ProofResponse {
    pub leaf_hash: [u8; 32],
    /// Sibling hashes from leaf to root (btv-types::MerkleProof.path format).
    pub proof: Vec<[u8; 32]>,
    pub root: [u8; 32],
    /// Complete btv-types::MerkleProof for wire consumption.
    /// btv-judicial can deserialize this directly via serde.
    pub wire_proof: btv_types::MerkleProof,
}

pub async fn get_proof(
    State(state): State<Arc<AppState>>,
    Path(index): Path<u64>,
) -> Result<Json<ProofResponse>, axum::http::StatusCode> {
    let proof = state.store.proof(index)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    let leaf = state.store.leaf_at(index)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    let root = state.store.root();

    let wire_proof = crate::merkle::to_wire_proof(proof.clone(), index);

    Ok(Json(ProofResponse {
        leaf_hash: leaf,
        proof,
        root,
        wire_proof,
    }))
}

// ── Router ─────────────────────────────────────────────────────────────────────────────────

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/append", post(append))
        .route("/root", get(get_root))
        .route("/proof/{index}", get(get_proof))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

    #[test]
    fn proof_response_is_btv_types_compatible() {
        let store = Arc::new(InMemoryStore::new());

        for i in 0u8..4 {
            store.append([i; 32]);
        }

        let proof = store.proof(0).unwrap();
        let root = store.root();
        let leaf = store.leaf_at(0).unwrap();

        let btv_proof = btv_types::MerkleProof {
            path: proof.clone(),
            leaf_index: 0,
        };
        assert!(
            btv_types::verify_merkle_inclusion(&root, &leaf, &btv_proof),
            "btv-sigma API proof failed btv-types verification!"
        );
    }

    #[test]
    fn wire_proof_serialization_roundtrip() {
        let proof = btv_types::MerkleProof {
            path: vec![[1u8; 32], [2u8; 32]],
            leaf_index: 42,
        };
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: btv_types::MerkleProof = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.leaf_index, 42);
        assert_eq!(deserialized.path.len(), 2);
    }

    #[test]
    fn wire_proof_matches_proof_field() {
        let store = Arc::new(InMemoryStore::new());
        for i in 0u8..8 {
            store.append([i; 32]);
        }

        for idx in 0..8u64 {
            let proof = store.proof(idx).unwrap();
            let wire = btv_types::MerkleProof { path: proof.clone(), leaf_index: idx };
            assert_eq!(wire.path, proof, "wire_proof.path must equal proof for index {}", idx);
            assert_eq!(wire.leaf_index, idx);
        }
    }
}
