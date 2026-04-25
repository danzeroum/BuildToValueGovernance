//! `InclusionReceipt` — cryptographic proof of inclusion in Σ.
//!
//! Paper 2, §III-B + Cases A–C of Theorem IV:
//! - Case A: struct-literal construction impossible (fields private, E0451)
//! - Case B: `new_verified` is `pub(crate)` — only `LogClient` can construct (E0603)
//! - Case C: `#[must_use]` prevents silent dropping (ephemeral verdict)
//!
//! Structural mirror of `EvidenceToken` from Phase 1 (Paper 1, Axiom 4.4).

/// A cryptographically-verified receipt confirming a verdict's inclusion in Σ.
///
/// Linear resource: must be consumed by `DeliveryToken::seal` — cannot be
/// cloned, copied, or silently dropped.
#[must_use = "InclusionReceipt must be consumed by DeliveryToken::seal — \
              dropping it produces an ephemeral verdict with no persistence guarantee \
              (Paper 2, Case C)"]  
pub struct InclusionReceipt {
    log_index:    u64,         // PRIVATE
    merkle_root:  [u8; 32],   // PRIVATE
    signature:    [u8; 64],   // PRIVATE — Ed25519 by Log Authority
    timestamp:    u64,         // PRIVATE
}

impl InclusionReceipt {
    /// Only callable within btv-core — invoked by `LogClient` after signature verification.
    /// External crates cannot forge a receipt without a valid Ed25519 signature.
    // TODO(Phase 2): LogClient::submit() will call this after verifying the Log Authority sig.
    #[allow(dead_code)]
    pub(crate) fn new_verified(
        log_index:   u64,
        merkle_root: [u8; 32],
        signature:   [u8; 64],
        timestamp:   u64,
    ) -> Self {
        Self { log_index, merkle_root, signature, timestamp }
    }

    /// Export to wire format for persistence in Σ and judicial verification.
    pub fn to_wire(&self) -> btv_types::InclusionReceiptWire {
        btv_types::InclusionReceiptWire {
            log_index:   self.log_index,
            merkle_root: self.merkle_root,
            signature:   self.signature,
            timestamp:   self.timestamp,
        }
    }

    // TODO(Phase 2): consumed by DeliveryToken::seal and judicial audit path.
    #[expect(dead_code, reason = "consumed by DeliveryToken::seal (Phase 2, not yet implemented)")]
    pub(crate) fn log_index(&self)    -> u64        { self.log_index }
    #[expect(dead_code, reason = "consumed by DeliveryToken::seal (Phase 2, not yet implemented)")]
    pub(crate) fn merkle_root(&self)  -> &[u8; 32]  { &self.merkle_root }
    #[expect(dead_code, reason = "consumed by DeliveryToken::seal (Phase 2, not yet implemented)")]
    pub(crate) fn signature(&self)    -> &[u8; 64]  { &self.signature }
}

// Explicitly NOT implementing Clone, Copy, Default.
// The absence of Clone is the primary linear-resource enforcement mechanism.
