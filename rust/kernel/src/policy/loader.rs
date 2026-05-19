//! PolicyWatcher — Ed25519-verified hot-reload of policy YAML (ADR-064).
//!
//! Separation of powers: the Ethics Committee holds the signing key (private);
//! the Executive server holds only the verifying key (public). A compromised
//! server cannot forge a policy because it never possesses the private key.
//!
//! Fail-secure: every reload path requires a valid signature before parsing.
//! An invalid or missing signature never produces a `Policy`.

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use thiserror::Error;

use crate::policy::Policy;

#[derive(Debug, Error)]
pub enum PolicyLoadError {
    #[error("Ed25519 signature verification failed — policy rejected")]
    InvalidSignature,
    #[error("Policy YAML parse error: {0}")]
    ParseError(#[from] serde_yaml::Error),
    #[error("Verifying key is invalid: {0}")]
    InvalidKey(String),
}

/// Hot-reload watcher that verifies Ed25519 signatures before parsing policy YAML.
pub struct PolicyWatcher {
    verifying_key: VerifyingKey,
}

impl PolicyWatcher {
    /// Construct from a 32-byte compressed Ed25519 public key (as used by dalek).
    pub fn new(pubkey_bytes: &[u8; 32]) -> Result<Self, PolicyLoadError> {
        let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
            .map_err(|e| PolicyLoadError::InvalidKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Verify `sig_bytes` over `yaml_bytes`, then parse into `Policy`.
    ///
    /// Signature must be produced by the Ethics Committee's private key
    /// (Ed25519, 64 bytes). Parsing only occurs after verification succeeds.
    pub fn verify_and_load(
        &self,
        yaml_bytes: &[u8],
        sig_bytes: &[u8; 64],
    ) -> Result<Policy, PolicyLoadError> {
        let sig = Signature::from_bytes(sig_bytes);
        self.verifying_key
            .verify(yaml_bytes, &sig)
            .map_err(|_| PolicyLoadError::InvalidSignature)?;
        serde_yaml::from_slice(yaml_bytes).map_err(PolicyLoadError::ParseError)
    }
}
