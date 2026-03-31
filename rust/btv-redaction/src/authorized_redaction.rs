//! Verificação de autorização do titular dos dados (Paper 3, Phase 1).
//!
//! Cada entrada de redação deve carregar a assinatura Ed25519 do titular,
//! provando que ele autorizou a remocao DESTA entrada específica.
use ed25519_dalek::{VerifyingKey, Verifier, Signature};

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("Invalid signature for entry {0:?}")]
    InvalidSignature([u8; 32]),
    #[error("Group label mismatch: expected {expected}, got {actual}")]
    GroupMismatch { expected: String, actual: String },
}

pub struct AuthorizationVerifier;

impl AuthorizationVerifier {
    /// Mensagem assinada: verdict_hash || group_label || \0 || timestamp_le || "REQUEST_ERASURE"
    pub fn verify_entry(
        entry: &super::group_stats::RedactionEntry,
        expected_group: &str,
        timestamp: u64,
    ) -> Result<(), AuthorizationError> {
        if entry.group_label != expected_group {
            return Err(AuthorizationError::GroupMismatch {
                expected: expected_group.into(),
                actual:   entry.group_label.clone(),
            });
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(&entry.verdict_hash);
        msg.extend_from_slice(entry.group_label.as_bytes());
        msg.push(0);
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg.extend_from_slice(b"REQUEST_ERASURE");

        let pubkey = VerifyingKey::from_bytes(&entry.subject_pubkey)
            .map_err(|_| AuthorizationError::InvalidSignature(entry.verdict_hash))?;
        let sig = Signature::from_bytes(&entry.subject_signature);

        pubkey.verify(&msg, &sig)
            .map_err(|_| AuthorizationError::InvalidSignature(entry.verdict_hash))
    }

    /// Verifica todas as entradas de um batch.
    pub fn verify_batch(
        entries: &[super::group_stats::RedactionEntry],
        group_lookup: &[&str],
        timestamp: u64,
    ) -> Result<(), AuthorizationError> {
        for (i, entry) in entries.iter().enumerate() {
            let expected = group_lookup.get(i).copied().unwrap_or("");
            Self::verify_entry(entry, expected, timestamp)?;
        }
        Ok(())
    }
}
