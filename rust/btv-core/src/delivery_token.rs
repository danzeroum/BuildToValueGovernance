//! `DeliveryToken` — the sole authorisation to deliver a decision to an end-user.
//!
//! Paper 2, Eq.(1): `DeliveryToken ⊸ (V ⊗ R)`
//!
//! Construction requires consuming BOTH a `&Verdict` AND an `InclusionReceipt`.
//! If the log is unavailable, no receipt can be obtained, and this function
//! cannot be called — the system fails securely (Paper 2, Corollary IV-B).
use crate::inclusion_receipt::InclusionReceipt;
use crate::verdict::Verdict;

/// Seals a verdict with its inclusion receipt, producing the only type
/// that may be delivered to an end-user.
///
/// All fields private — struct-literal construction is E0451.
pub struct DeliveryToken {
    verdict_record: btv_types::VerdictRecord,          // PRIVATE
    receipt_wire:   btv_types::InclusionReceiptWire,   // PRIVATE
}

/// Error returned when sealing fails.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("Verdict HMAC integrity check failed — possible tampering")]
    IntegrityFailure,
}

impl DeliveryToken {
    /// Seal a verdict with its inclusion receipt.
    ///
    /// `receipt` is taken BY VALUE and consumed — the only path to a `DeliveryToken`.
    /// Verifies the verdict's HMAC seal before accepting it.
    pub fn seal(
        verdict: &Verdict,
        receipt: InclusionReceipt,   // consumed (moved) — linear resource
    ) -> Result<Self, SealError> {
        if !verdict.verify_integrity() {
            return Err(SealError::IntegrityFailure);
        }
        Ok(Self {
            verdict_record: verdict.to_record(),
            receipt_wire:   receipt.to_wire(),
        })
    }

    /// Deliver: consumes `self` (one-time delivery, replay impossible).
    /// After this call, no `DeliveryToken` exists.
    pub fn deliver(self) -> DeliveryPayload {
        DeliveryPayload {
            verdict: self.verdict_record,
            receipt: self.receipt_wire,
        }
    }
}

/// The payload delivered to the end-user. All fields are public for read access.
pub struct DeliveryPayload {
    pub verdict: btv_types::VerdictRecord,
    pub receipt: btv_types::InclusionReceiptWire,
}
