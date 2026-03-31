//! Ed25519 signing with key isolation.
//!
//! Paper 2, Axiom III-C: "K_priv is not accessible to the System Operator."
//! The `LogSigner` struct never exposes the private key material.
//! In production, replace `generate()` with HSM/TPM-backed key loading.
//!
//! # ed25519-dalek v2 note
//! `SigningKey::generate()` was removed from the public API in v2.
//! The canonical replacement is to fill 32 random bytes via `RngCore`
//! and construct with `SigningKey::from_bytes(&secret)`.
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature};
use rand::rngs::OsRng;
use rand::RngCore;

/// Holds the Ed25519 signing key. Never Clone, never Serialize.
/// The signing key field is private and cannot be extracted.
pub struct LogSigner {
    signing_key: SigningKey, // NEVER exported, NEVER serialised (Paper 2 Axiom III-C)
}

impl LogSigner {
    /// Generate a fresh ephemeral key pair using the OS CSPRNG.
    ///
    /// Uses `OsRng::fill_bytes` → `SigningKey::from_bytes` instead of the
    /// removed `SigningKey::generate()` API (ed25519-dalek v2 breaking change).
    ///
    /// In production, load from HSM — see DEPLOYMENT.md.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self { signing_key: SigningKey::from_bytes(&secret) }
    }

    /// The verifying (public) key — printed at startup for out-of-band pinning.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign `message`. The signing key never leaves this struct.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

// Explicitly no Clone, Copy, Serialize — compile-time enforcement.
