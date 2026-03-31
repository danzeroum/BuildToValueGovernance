//! `EscalatedVerdict` — the product of consuming an `OperatorToken`.
//!
//! Paper 1, Corollary 4.8: human escalation as the only well-typed alternative
//! when `EvidenceToken` is unavailable. All fields private → struct literal is E0451.

use crate::operator_token::OperatorToken;

/// A materialized escalation verdict — the product of consuming an `OperatorToken`.
///
/// All fields are private. Only constructible via `EscalatedVerdict::new`.
pub struct EscalatedVerdict {
    operator_id: String,   // private
    reason: String,        // private
    #[allow(dead_code)] // Integrity field — verified in Phase 4 (btv-judicial)
    hmac_seal: [u8; 32],   // private
}

impl EscalatedVerdict {
    /// The sole constructor. Consumes `operator` by value (move semantics).
    ///
    /// After this call, the `OperatorToken` is gone — it cannot be reused
    /// (reuse would be compile error E0382).
    pub fn new(operator: OperatorToken, reason: String) -> Self {
        let (id, seal) = operator.consume();
        Self { operator_id: id, reason, hmac_seal: seal }
    }

    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}
