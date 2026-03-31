//! Verificação Ed25519 do InclusionReceiptWire.
//!
//! Paper 2, Case D: "LogClient é construído com VerifyingKey obtida out-of-band."
//! O Judiciário verifica a assinatura usando a mesma verifying key do LogClient
//! mas distribuída por canal judicial independente.
use ed25519_dalek::{VerifyingKey, Verifier, Signature};
use crate::hmac_verify::JudicialError;

/// Verifica a assinatura Ed25519 do InclusionReceiptWire.
#[derive(Clone)]
pub struct ReceiptVerifier {
    verifying_key: VerifyingKey,
}

impl ReceiptVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Constrói a partir da variável de ambiente `BTV_LOG_VERIFYING_KEY` (hex 32 bytes).
    pub fn from_env() -> Result<Self, JudicialError> {
        let key_hex = std::env::var("BTV_LOG_VERIFYING_KEY")
            .map_err(|_| JudicialError::ConfigurationMissing("BTV_LOG_VERIFYING_KEY".into()))?;
        let key_bytes: [u8; 32] = hex::decode(&key_hex)
            .map_err(|e| JudicialError::ConfigurationMissing(format!("hex decode: {e}")))?;
            .try_into()
            .map_err(|_| JudicialError::ConfigurationMissing("Key must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| JudicialError::ConfigurationMissing(format!("Ed25519: {e}")))?;
        Ok(Self::new(vk))
    }

    /// Verifica a assinatura Ed25519 no receipt.
    ///
    /// Mensagem assinada: index || root || verdict_hash || timestamp
    pub fn verify(
        &self,
        receipt: &btv_types::InclusionReceiptWire,
        verdict_hash: &[u8; 32],
    ) -> Result<bool, JudicialError> {
        let mut msg = Vec::with_capacity(80);
        msg.extend_from_slice(&receipt.log_index.to_le_bytes());
        msg.extend_from_slice(&receipt.merkle_root);
        msg.extend_from_slice(verdict_hash);
        msg.extend_from_slice(&receipt.timestamp.to_le_bytes());

        let sig = Signature::from_bytes(&receipt.signature);
        self.verifying_key
            .verify(&msg, &sig)
            .map(|_| true)
            .map_err(|e| JudicialError::VerificationFailed(format!("Ed25519: {e}")))
    }
}
