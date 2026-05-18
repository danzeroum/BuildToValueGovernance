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

// ── Cryptographic utilities shared by btv-core and btv-judicial ──────────────────
// v2.3.1: Centralized to eliminate constant_time_eq duplication (ADR DRY enforcement).
pub mod crypto_utils;

// ── Merkle verification (usable by btv-judicial without importing btv-sigma) ─────
pub mod merkle_verify;
pub use merkle_verify::verify_merkle_inclusion;

// ── Primitive hash wrapper ─────────────────────────────────────────────

/// A BLAKE3 hash in wire format. All bytes are public — read-only digest, not a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3Hash(pub [u8; 32]);

// ── Decision + Risk ───────────────────────────────────────────────────────────────────

/// Decision emitted by the Executive pipeline.
///
/// NEVER reorder — historical Ledger data depends on these repr(u8) values.
/// - `Allow`: approved by policy.
/// - `Deny`:  rejected by policy (calibrated risk). 24h contestation SLA.
/// - `Block`: active threat — NOT a policy rejection. Triggers immediate Trust Score
///   penalty and security alert. Distinct from Deny to prevent misclassification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Decision {
    Allow = 0,
    Deny  = 1,
    Block = 2,
}

impl Decision {
    /// True only for Block — triggers security alert in the Ledger.
    pub fn requires_security_alert(&self) -> bool {
        matches!(self, Decision::Block)
    }

    /// All decisions are contestable within the 24h SLA (LGPD Art. 20).
    /// Investigation priority differs, not contestability.
    pub fn is_contestable(&self) -> bool {
        true
    }
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

// ── Bias Declaration (ADR-060) ────────────────────────────────────────────────────────────────────

/// An equity deviation detected and accepted by the Ethics Committee with documented justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownDisparity {
    /// Affected group (e.g. "idade > 60", "idioma != pt-BR").
    pub group: String,
    /// Measured deviation in absolute percentage points.
    pub disparity_magnitude_pct: f32,
    /// Justification approved by the Ethics Committee.
    pub ethical_justification: String,
    /// Unix timestamp (seconds) of Ethics Committee approval.
    pub approved_at: u64,
}

/// Structured declaration of calibrated biases attached to every VerdictRecord.
///
/// Uses Vec — heap allocation. NOT for hot-path TechnicalEvidence (ADR-063 will define
/// BiasDeclarationFixed for that purpose).
/// Valid contexts: VerdictRecord (serialised), AppealRecord (off-chain), API responses.
///
/// Philosophical foundation: Levinas (responsibility to the Other) + Gilligan (ethics of care).
/// Declaration is mandatory — it is the system's ethical contract with each affected person.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiasDeclaration {
    /// Calibrated False Positive rate (0.0–1.0). FP = Deny for something that should be Allow.
    pub false_positive_rate: f32,
    /// Calibrated False Negative rate (0.0–1.0). FN = Allow for something that should be Deny.
    pub false_negative_rate: f32,
    /// Groups for which this model was explicitly validated. Empty list = UNVALIDATED.
    pub validated_groups: Vec<String>,
    /// Equity deviations detected and accepted by the Ethics Committee.
    pub known_disparities: Vec<KnownDisparity>,
    /// Version of the bias measurement tool/methodology used.
    pub measurement_tool_version: String,
}

impl BiasDeclaration {
    /// Bootstrap placeholder. The string "UNVALIDATED" in validated_groups triggers
    /// Dashboard audit alerts and is detectable via `is_bootstrap()`.
    /// Must be replaced with real measurements before any external PoC.
    pub fn bootstrap_unvalidated() -> Self {
        Self {
            false_positive_rate: 0.0,
            false_negative_rate: 0.0,
            validated_groups: vec!["UNVALIDATED — completar antes do PoC".to_string()],
            known_disparities: vec![],
            measurement_tool_version: "bootstrap-0.0.0".to_string(),
        }
    }

    /// Returns true if this declaration is still in bootstrap state (not yet validated).
    pub fn is_bootstrap(&self) -> bool {
        self.validated_groups.iter().any(|g| g.starts_with("UNVALIDATED"))
    }
}

// ── Negotiation Deadlock (ADR-061) ────────────────────────────────────────────────────────────────

/// Structured reason for a Decision::Block originating from a negotiation deadlock.
///
/// Produced by `negotiation_engine.py` via the `/internal/v1/block-decision` endpoint,
/// then converted to this type by the Axum handler before being written to the Ledger.
/// Never produced directly by `DecisionMaker::decide()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationDeadlockReason {
    /// Number of rounds until deadlock. Should equal max_rounds (typically 3).
    pub rounds_exhausted: u8,
    /// IDs of agents that failed to reach consensus.
    pub agent_ids: Vec<String>,
    /// BLAKE3 hash of the last rejected policy proposal per agent.
    /// Index i corresponds to agent_ids[i].
    pub last_proposal_hashes: Vec<[u8; 32]>,
    /// Unix timestamp (seconds) when negotiation started.
    pub negotiation_started_at: u64,
    /// Unix timestamp (seconds) when deadlock was declared.
    pub deadlocked_at: u64,
}

// ── Appeal Record (ADR-062) ───────────────────────────────────────────────────────────────────────

/// Off-chain contestation record. Persisted in `appeals.db`, never in the main Ledger (btv-sigma).
///
/// Authenticity is verified at display time:
///   blake3(explanation_text) == VerdictRecord.explanation_hash
///
/// The hash in the Ledger is cryptographic proof against retroactive tampering of the text.
/// Legal foundation: LGPD Art. 20, EU AI Act Art. 14.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppealRecord {
    /// Link key to the Ledger. Must equal VerdictRecord.evidence_hash for the corresponding entry.
    pub evidence_hash: [u8; 32],
    /// Full explanation text produced by DecisionMaker::explain().
    /// BLAKE3 of this field must equal VerdictRecord.explanation_hash.
    pub explanation_text: String,
    /// Full BiasDeclaration (Vec allowed — off-chain context).
    pub bias_declaration: BiasDeclaration,
    /// Structured deadlock reason if the decision was a negotiation Block. None for scanner decisions.
    pub deadlock_reason: Option<NegotiationDeadlockReason>,
    /// Contestation token: hex(blake3::keyed_hash(SERVER_APPEAL_KEY, evidence_hash)).
    /// Deterministic and server-verifiable without a DB lookup.
    pub appeal_token: String,
    /// Unix timestamp (seconds) of the contestation SLA deadline: created_at + 86400.
    pub appeal_sla_deadline: u64,
    /// Unix timestamp (seconds) when this record was created.
    pub created_at: u64,
}

impl AppealRecord {
    /// Returns true if the contestation window is still open.
    pub fn is_within_sla(&self, now: u64) -> bool {
        now < self.appeal_sla_deadline
    }
}

// ── Verdict ──────────────────────────────────────────────────────────────────────────────────────

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
    /// ADR-060: Mandatory calibrated-bias declaration for this decision.
    /// Use BiasDeclaration::bootstrap_unvalidated() during transition.
    pub bias_declaration:    BiasDeclaration,
}

// ── Log-authority (Σ) types ─────────────────────────────────────────────────────────────

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

// ── Delivery (Phase 3) ─────────────────────────────────────────────────────────────────────────

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

// ── Redaction (Phase 5) ─────────────────────────────────────────────────────────────────────

/// Wire format de RedactionReceipt — verificável pelo Judiciário (btv-judicial).
///
/// Contém a prova ZK (Groth16/PLONK) que garante
/// |q_g^antes − q_g^depois| ≤ ε para TODOS os grupos protegidos g,
/// sem revelar as estatísticas reais (Paper 3, Theorem 4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionReceiptWire {
    /// ID único do batch de redação.
    pub batch_id: String,
    /// Número de entradas redacionadas.
    pub entries_count: usize,
    /// Pedersen commitment ANTES da redação (comprimido, 32 bytes).
    pub commitment_before: [u8; 32],
    /// Pedersen commitment APÓS a redação.
    pub commitment_after: [u8; 32],
    /// Tolerância ε usada para este batch.
    pub epsilon: f64,
    /// Grupos protegidos afetados.
    pub affected_groups: Vec<String>,
    /// Bytes da prova ZK (~3.2kB para Barretenberg).
    /// Vazio no modo direct (sem Noir) — integração completa na Fase 5 (Semanas 18-30).
    pub proof_bytes: Vec<u8>,
    /// Inputs públicos usados para verificação (excluindo witness).
    pub public_inputs: Vec<[u8; 32]>,
    /// Timestamp da redação.
    pub timestamp: u64,
    /// Assinatura Ed25519 da autoridade redatora.
    #[serde(with = "serde_bytes_64")]
    pub authority_signature: [u8; 64],
    /// Chave pública da autoridade redatora.
    pub authority_pubkey: [u8; 32],
}

// ── Governance / mandate types ─────────────────────────────────────────────────────────

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
