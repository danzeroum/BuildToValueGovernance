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

/// A BLAKE3 hash in wire format. All bytes are public — read-only digest, not a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3Hash(pub [u8; 32]);

// ── Decision + Risk ──────────────────────────────────────────────────────────────────

/// Binary decision emitted by the Executive pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Decision {
    Allow = 0,
    Deny  = 1,
}

/// Risk level produced by the gatekeeper scan (Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RiskLevel {
    Safe     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s < 0.2 => Self::Safe,
            s if s < 0.4 => Self::Low,
            s if s < 0.6 => Self::Medium,
            s if s < 0.8 => Self::High,
            _             => Self::Critical,
        }
    }
}

// ── Verdict ───────────────────────────────────────────────────────────────────────────

/// Serialised verdict record — wire format persisted to Σ and verified by btv-judicial.
/// Construction requires `btv-core::Verdict::new` which consumes a linear `E ⊗ C`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub evidence_hash:       Blake3Hash,
    pub decision:            Decision,
    pub explanation_hash:    Blake3Hash,
    /// HMAC-SHA256 tag binding evidence_hash + decision + explanation.
    pub hmac_tag:            [u8; 32],
    /// Version of MandateToken in effect (placeholder: 0 until Phase 6).
    pub legislative_version: u64,
}

// ── Log-authority (Σ) types ─────────────────────────────────────────────────────────

/// Merkle inclusion proof for independent verification by btv-judicial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub path:       Vec<[u8; 32]>,
    pub leaf_index: u64,
}

/// Receipt issued by Σ confirming a verdict's inclusion in the append-only log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionReceiptWire {
    pub log_index:   u64,
    pub merkle_root: [u8; 32],
    /// Ed25519 signature by the Σ authority key.
    #[serde(with = "serde_bytes_64")]
    pub signature:   [u8; 64],
    pub timestamp:   u64,
}

// ── Delivery (Phase 3) ────────────────────────────────────────────────────────────────

/// The payload delivered to the end-user. Contains all public data.
/// Integrity is guaranteed by HMAC seal (verdict) and Ed25519 signature (receipt),
/// not by Rust's type system — btv-judicial (Phase 4) verifies both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryPayload {
    pub verdict: VerdictRecord,
    pub receipt: InclusionReceiptWire,
}

/// Audit trail entry for observability / btv-judicial ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub verdict_hash:    [u8; 32],
    pub decision:        Decision,
    pub risk_level:      RiskLevel,
    pub composite_risk:  f32,
    pub findings_count:  usize,
    pub log_index:       u64,
    pub timestamp_us:    u64,
    pub latency_us:      u64,
}

// ── Governance / mandate types ────────────────────────────────────────────────────

/// Branch roles participating in MandateToken ratification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BranchRole {
    Legislative = 0,
    Judicial    = 1,
    ExecutiveRep = 2,
}

/// One ratification signature in a MandateToken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureWire {
    pub signer_role: BranchRole,
    pub pubkey:      [u8; 32],
    #[serde(with = "serde_bytes_64")]
    pub signature:   [u8; 64],
}

/// MandateToken wire format — three-party ratification (Fase 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateWire {
    pub legislative_version: u64,
    pub expiry_utc:          u64,
    pub ratification_sigs:   [SignatureWire; 3],
}
