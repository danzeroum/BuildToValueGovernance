//! Tripartite Ratification — verifies that all three constitutional branches
//! have signed a mandate amendment.
//!
//! Paper 6, Definition 3.3: "Valid(ΔL*) ⇔ σ_L ∧ σ_J ∧ σ_Erep"
//! Paper 5, Corollary 3.6:  "P_L ∩ P_E ∩ P_J = ∅"

use ed25519_dalek::{Signature, VerifyingKey, Verifier};

use crate::mandate::{AmendmentId, RatificationProof};

// ── Branch enum ──────────────────────────────────────────────────────────────

/// The three constitutional branches of the Algorithmic Republic.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash,
    serde::Serialize, serde::Deserialize,
)]
pub enum Branch {
    Legislative,
    Judicial,
    ExecutiveRepresentative,
}

// ── BranchKeys ───────────────────────────────────────────────────────────────

/// One Ed25519 verifying key per branch.
///
/// Paper 5, Corollary 3.6: keys are disjoint — no cross-sharing.
#[derive(Debug, Clone)]
pub struct BranchKeys {
    pub legislative:    VerifyingKey,
    pub judicial:       VerifyingKey,
    pub executive_rep:  VerifyingKey,
}

// ── Verification ─────────────────────────────────────────────────────────────

/// Verify that a `RatificationProof` carries valid signatures from all three
/// constitutional branches.
///
/// The canonical message signed by each branch is:
///   `amendment_id || nonce || timestamp_le`
///
/// Returns `false` on **any** failure — fail-secure.
pub fn verify_tripartite_signatures(proof: &RatificationProof) -> bool {
    let message = build_ratification_message(
        &proof.amendment,
        &proof.nonce,
        &proof.timestamp,
    );

    verify_one(&proof.legislative_pubkey,   &proof.legislative_sig,   &message)
        && verify_one(&proof.judicial_pubkey,      &proof.judicial_sig,      &message)
        && verify_one(&proof.executive_rep_pubkey, &proof.executive_rep_sig, &message)
}

// ── private helpers ──────────────────────────────────────────────────────────

fn verify_one(pubkey_bytes: &[u8; 32], sig_bytes: &[u8; 64], message: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(pubkey_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(sig_bytes);
    key.verify(message, &sig).is_ok()
}

/// Build the canonical message that all three branches must sign.
///
/// Canonical form: `amendment_tag || nonce[32] || timestamp_le[8]`
fn build_ratification_message(
    amendment: &AmendmentId,
    nonce:     &[u8; 32],
    timestamp: &chrono::DateTime<chrono::Utc>,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    match amendment {
        AmendmentId::Genesis => msg.extend_from_slice(b"GENESIS\x00"),
        AmendmentId::Amendment(n) => {
            msg.extend_from_slice(b"AMEND:\x00\x00");
            msg.extend_from_slice(&n.to_le_bytes());
        }
    }
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&timestamp.timestamp().to_le_bytes());
    msg
}
