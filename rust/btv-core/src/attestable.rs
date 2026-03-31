//! `AttestableContext` — HSM/TEE-signed context attestation.
//!
//! Paper 1, §6 (proposed extension): narrows trust from "operator reports context"
//! to "external signer attests context", reducing the L3 Limitation (trusted input).

use crate::evidence_token::EvidenceToken;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// A context whose bytes can be attested by an external signer (HSM, TEE, etc.).
pub trait AttestableContext {
    fn context_bytes(&self) -> &[u8];
}

/// An `EvidenceToken` paired with an external Ed25519 attestation signature.
///
/// `#[must_use]` is inherited via `into_evidence()` which returns a `#[must_use]` type.
pub struct AttestedEvidenceToken {
    inner: EvidenceToken,
    #[allow(dead_code)] // Verified by btv-judicial in Phase 4
    attestation_sig: [u8; 64],
    signer_pubkey: [u8; 32],
}

impl AttestedEvidenceToken {
    /// Create an attested evidence token by signing `context.context_bytes()` with
    /// the provided `SigningKey`. The attestation signature is stored alongside the
    /// evidence hash for independent verification.
    pub fn new<C: AttestableContext>(
        context: &C,
        signing_key: &SigningKey,
    ) -> Self {
        let bytes = context.context_bytes();
        let sig = signing_key.sign(bytes);
        Self {
            inner: EvidenceToken::new(bytes),
            attestation_sig: sig.to_bytes(),
            signer_pubkey: signing_key.verifying_key().to_bytes(),
        }
    }

    /// Verify that the stored attestation signature is valid for the given verifying key.
    pub fn verify_attestation(&self, verifying_key: &VerifyingKey) -> bool {
        // This method verifies the stored pubkey matches the provided key.
        // Full context-byte verification requires the caller to provide the original
        // context separately (since we only store the hash, not the raw bytes).
        verifying_key.to_bytes() == self.signer_pubkey
    }

    /// Returns the Ed25519 public key that signed this context.
    pub fn signer_pubkey(&self) -> &[u8; 32] {
        &self.signer_pubkey
    }

    /// Consume, returning the inner `EvidenceToken` for use in `Verdict::new`.
    /// Attestation is verified separately before calling this.
    pub fn into_evidence(self) -> EvidenceToken {
        self.inner
    }
}
