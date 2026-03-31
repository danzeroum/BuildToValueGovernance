//! HTTP API for btv-sigma.
//!
//! Endpoints:
//! - POST /append          — append a verdict hash, get signed receipt
//! - GET  /root            — current Merkle root + tree size
//! - GET  /proof/{index}   — Merkle inclusion proof for leaf at index
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

// ── POST /append ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AppendRequest {
    pub verdict_hash: [u8; 32],
}

#[derive(Serialize)]
pub struct AppendResponse {
    pub index: u64,
    pub root: [u8; 32],
    #[serde(with = "btv_types::serde_bytes_64_pub")]
    pub signature: [u8; 64], // Ed25519 over (index || root || verdict_hash || timestamp)
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

// ── GET /root ─────────────────────────────────────────────────────────────────

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

// ── GET /proof/{index} ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ProofResponse {
    pub leaf_hash: [u8; 32],
    pub proof: Vec<([u8; 32], String)>, // (sibling_hash, "left"|"right")
    pub root: [u8; 32],
}

pub async fn get_proof(
    State(state): State<Arc<AppState>>,
    Path(index): Path<u64>,
) -> Result<Json<ProofResponse>, axum::http::StatusCode> {
    let proof = state.store.proof(index)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    let leaf = state.store.leaf_at(index)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;

    Ok(Json(ProofResponse {
        leaf_hash: leaf,
        proof: proof.into_iter().map(|(h, s)| {
            let label = match s {
                crate::merkle::Side::Left  => "left",
                crate::merkle::Side::Right => "right",
            };
            (h, label.to_string())
        }).collect(),
        root: state.store.root(),
    }))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/append", post(append))
        .route("/root", get(get_root))
        .route("/proof/{index}", get(get_proof))
        .with_state(state)
}
