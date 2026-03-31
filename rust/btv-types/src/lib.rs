//! `btv-types` — Shared wire-format types for the BuildToValue crate graph.
//!
//! **Boundary rule**: This crate contains ONLY structs with `pub` fields, enums,
//! and verification traits. No `pub(crate)` constructors, no linear resources,
//! no capability tokens. Any crate may import this without acquiring build capabilities.
//!
//! Resolves Tension 4: `btv-judicial` can import this crate without ever touching
//! the constructors that live in `btv-core`.
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

// Custom serde for [u8; 64] — serde only supports arrays up to [T; 32] natively.
mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(arr: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(arr)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        let mut arr = [0u8; 64];
        let len = bytes.len().min(64);
        arr[..len].copy_from_slice(&bytes[..len]);
        Ok(arr)
    }
}

/// Public re-export so btv-sigma and btv-core can use the same serde helper
/// without duplicating the implementation.
pub mod serde_bytes_64_pub {
    pub use super::serde_bytes_64::serialize;
    pub use super::serde_bytes_64::deserialize;
}

// ── Merkle verification (usable by btv-judicial without importing btv-sigma) ─────
pub mod merkle_verify;
pub use merkle_verify::verify_merkle_inclusion;

// ── Primitive hash wrapper ────────────────────────────────────────────────────

/// A BLAKE3 hash in wire format. All bytes are public — this is a read-only digest,
/// not a capability token. External crates can hold and inspect it but cannot forge
/// a new one (that requires `btv-core::Blake3Hash::of`, which is `pub(crate)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3Hash(pub [u8; 32]);

// ── Verdict types ──────────────────────────────────────────────────────────────────

/// Binary decision emitted by the Executive pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Decision {
    Allow = 0,
    Deny = 1,
}

/// Serialised verdict record — the wire format persisted to Σ and verified by
/// `btv-judicial`. All fields are public for read access; construction requires
/// `btv-core::Verdict::new` which consumes a linear `EvidenceToken ⊗ ComplianceToken`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub evidence_hash: Blake3Hash,
    pub decision: Decision,
    pub explanation_hash: Blake3Hash,
    /// HMAC-SHA256 tag binding evidence_hash + decision + explanation.
    pub hmac_tag: [u8; 32],
    /// Version of the MandateToken in effect at decision time (placeholder: 0 until Phase 6).
    pub legislative_version: u64,
}

// ── Log-authority (Σ) types ──────────────────────────────────────────────────────────

/// Merkle inclusion proof for a verdict in the append-only log Σ.
/// Used by `btv-judicial` for independent verification without importing `btv-core`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub path: Vec<[u8; 32]>,
    pub leaf_index: u64,
}

/// Receipt issued by Σ confirming a verdict's inclusion in the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionReceiptWire {
    pub log_index: u64,
    pub merkle_root: [u8; 32],
    /// Ed25519 signature by the Σ authority key.
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
    pub timestamp: u64,
}

// ── Governance / mandate types ────────────────────────────────────────────────────

/// Branch roles participating in MandateToken ratification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BranchRole {
    Legislative = 0,
    Judicial = 1,
    ExecutiveRep = 2,
}

/// One ratification signature in a MandateToken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureWire {
    pub signer_role: BranchRole,
    pub pubkey: [u8; 32],
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

/// MandateToken wire format — publicable in Σ, verifiable by all branches.
/// Three-party ratification (Legislative + Judicial + ExecutiveRep) before any
/// Executive decision is authorised (Tension 2 / Tension 3 resolution, Phase 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateWire {
    pub legislative_version: u64,
    pub expiry_utc: u64,
    pub ratification_sigs: [SignatureWire; 3],
}
