//! Verificação do HMAC-SHA256 do VerdictRecord.
//!
//! Paper 5, §4.1: "J verifica o HMAC usando chave distribuída
//! independentemente do operador Executivo."
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Erros do Judiciário.
#[derive(Debug, thiserror::Error)]
pub enum JudicialError {
    #[error("Configuration missing: {0}")]
    ConfigurationMissing(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Log query failed: {0}")]
    LogQueryFailed(String),
}

/// Verifica o HMAC-SHA256 do VerdictRecord.
///
/// O Judiciário NÃO tem a chave HMAC do Executivo.
/// A chave é distribuída out-of-band via `BTV_HMAC_KEY`.
#[derive(Clone)]
pub struct HmacVerifier {
    key: Vec<u8>,
}

impl HmacVerifier {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Constrói a partir da variável de ambiente `BTV_HMAC_KEY`.
    pub fn from_env() -> Result<Self, JudicialError> {
        let key = std::env::var("BTV_HMAC_KEY")
            .map_err(|_| JudicialError::ConfigurationMissing("BTV_HMAC_KEY".into()))?;
        Ok(Self { key: key.into_bytes() })
    }

    /// Verifica o HMAC seal no VerdictRecord.
    ///
    /// Recalcula: HMAC-SHA256(key, evidence_hash || decision_byte || explanation_hash)
    /// Compara com constant-time comparison para prevenir timing oracle.
    pub fn verify(
        &self,
        verdict: &btv_types::VerdictRecord,
    ) -> Result<bool, JudicialError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| JudicialError::CryptoError(e.to_string()))?;

        mac.update(&verdict.evidence_hash.0);
        mac.update(&[verdict.decision as u8]);
        mac.update(&verdict.explanation_hash.0);

        let expected = mac.finalize().into_bytes();
        Ok(constant_time_eq(&verdict.hmac_tag, &expected.into()))
    }
}

/// Constant-time comparison — v2.3.1: delegates to btv-types::crypto_utils.
/// The Judicial uses the same BTV_HMAC_KEY as the Executive but verifies
/// independently — constitutional separation is preserved.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    btv_types::crypto_utils::constant_time_eq(a, b)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use btv_types::{Blake3Hash, Decision, VerdictRecord};

    fn make_verdict(hmac_tag: [u8; 32]) -> VerdictRecord {
        VerdictRecord {
            evidence_hash:       Blake3Hash([0x01; 32]),
            decision:            Decision::Allow,
            explanation_hash:    Blake3Hash([0x02; 32]),
            hmac_tag,
            legislative_version: 0,
        }
    }

    fn correct_hmac(key: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(&[0x01; 32]); // evidence_hash
        mac.update(&[0u8]);       // Decision::Allow
        mac.update(&[0x02; 32]); // explanation_hash
        mac.finalize().into_bytes().into()
    }

    #[test]
    fn valid_hmac_passes() {
        let key = b"test-hmac-key-for-unit-tests!!!!";
        let tag = correct_hmac(key);
        let verifier = HmacVerifier::new(key.to_vec());
        assert!(verifier.verify(&make_verdict(tag)).unwrap());
    }

    #[test]
    fn forged_hmac_fails() {
        let key = b"test-hmac-key-for-unit-tests!!!!";
        let verifier = HmacVerifier::new(key.to_vec());
        assert!(!verifier.verify(&make_verdict([0xFF; 32])).unwrap());
    }
}
