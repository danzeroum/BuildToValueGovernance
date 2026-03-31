//! `OperatorToken` — linear resource for human-escalation path.
//!
//! Paper 1, Corollary 4.8: "V_esc ⊸ (O ⊗ 1)"
//! When evidence is unavailable, a human operator can escalate by consuming an
//! `OperatorToken`. The token seals the operator identity with HMAC to prevent
//! forgery.

use crate::hmac::compute_seal;
use btv_types::Decision;

/// A linear resource encoding a human operator's authorization to escalate.
///
/// Same Axiom 4.4 constraints as `EvidenceToken`: no Clone, no Copy, must be used.
#[must_use = "OperatorToken must be consumed by EscalatedVerdict::new"]
pub struct OperatorToken {
    operator_id: String,
    hmac_seal: [u8; 32],
}

impl OperatorToken {
    /// Create a new operator token. The operator identity is sealed with HMAC
    /// using the `BTV_HMAC_KEY` to prevent forgery.
    pub fn new(operator_id: String) -> Self {
        let id_hash: [u8; 32] = *blake3::hash(operator_id.as_bytes()).as_bytes();
        let seal = compute_seal(
            &id_hash,
            &Decision::Allow, // sentinel value — not a real decision
            b"operator-escalation",
        );
        Self { operator_id, hmac_seal: seal }
    }

    /// Consume the token, returning the operator identity and its HMAC seal.
    /// `pub(crate)` — only `EscalatedVerdict::new` can call this (E0624 externally).
    pub(crate) fn consume(self) -> (String, [u8; 32]) {
        (self.operator_id, self.hmac_seal)
    }
}

// Explicitly NOT implementing Clone or Copy.
