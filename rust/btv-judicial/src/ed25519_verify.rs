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
            .map_err(|e| JudicialError::ConfigurationMissing(format!("hex decode: {e}")))?
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::RngCore;

    fn make_keypair() -> (SigningKey, VerifyingKey) {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn valid_signature_passes() {
        let (sk, vk) = make_keypair();
        let verifier = ReceiptVerifier::new(vk);

        let verdict_hash = [0x01u8; 32];
        let receipt = btv_types::InclusionReceiptWire {
            log_index:   0,
            merkle_root: [0u8; 32],
            signature:   [0u8; 64],
            timestamp:   0,
        };

        let mut msg = Vec::with_capacity(80);
        msg.extend_from_slice(&receipt.log_index.to_le_bytes());
        msg.extend_from_slice(&receipt.merkle_root);
        msg.extend_from_slice(&verdict_hash);
        msg.extend_from_slice(&receipt.timestamp.to_le_bytes());

        let sig = sk.sign(&msg);
        let signed_receipt = btv_types::InclusionReceiptWire {
            signature: sig.to_bytes(),
            ..receipt
        };

        assert!(verifier.verify(&signed_receipt, &verdict_hash).unwrap());
    }

    #[test]
    fn forged_signature_fails() {
        let (_, vk) = make_keypair();
        let verifier = ReceiptVerifier::new(vk);
        let receipt = btv_types::InclusionReceiptWire {
            log_index: 0, merkle_root: [0u8; 32],
            signature: [0u8; 64], timestamp: 0,
        };
        let result = verifier.verify(&receipt, &[0u8; 32]);
        assert!(result.is_err() || !result.unwrap());
    }
}
