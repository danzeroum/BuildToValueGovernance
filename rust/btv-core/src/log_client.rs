//! `LogClient` — HTTP client for btv-sigma with pinned Ed25519 key.
//!
//! Paper 2, Case D defence: the verifying key is obtained OUT-OF-BAND
//! (from the operator who runs btv-sigma, not from the log API itself).
//! The client refuses to accept any receipt whose signature does not
//! verify against the pinned key, preventing MITM attacks.
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use crate::inclusion_receipt::InclusionReceipt;

/// Error variants for log submission.
#[derive(Debug, thiserror::Error)]
pub enum LogClientError {
    #[error("Log server unavailable: {0}")]
    Unavailable(String),
    #[error("Invalid Ed25519 signature — possible MITM (Paper 2, Case D)")]
    InvalidSignature,
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Deserialisation error: {0}")]
    Deserialise(String),
}

/// HTTP client for btv-sigma with a pinned verifying key.
///
/// Construct with `LogClient::new(endpoint, pinned_key)` or
/// `LogClient::from_env()` for deployment convenience.
pub struct LogClient {
    endpoint:      String,
    verifying_key: VerifyingKey, // Pinned out-of-band — not fetched from the log
    http:          reqwest::Client,
}

impl LogClient {
    /// Construct with an explicitly pinned verifying key.
    /// The key MUST be obtained out-of-band (e.g. printed by btv-sigma at startup,
    /// distributed via BTV_LOG_VERIFYING_KEY env var from a trusted channel).
    pub fn new(endpoint: String, pinned_key: VerifyingKey) -> Self {
        Self {
            endpoint,
            verifying_key: pinned_key,
            http: reqwest::Client::new(),
        }
    }

    /// Construct from environment variables (deployment convenience).
    ///
    /// Required env vars:
    /// - `BTV_LOG_VERIFYING_KEY` — hex-encoded 32-byte Ed25519 verifying key
    ///
    /// Optional:
    /// - `BTV_LOG_ENDPOINT` (default: `http://localhost:3100`)
    pub fn from_env() -> Result<Self, LogClientError> {
        let endpoint = std::env::var("BTV_LOG_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:3100".to_string());

        let key_hex = std::env::var("BTV_LOG_VERIFYING_KEY")
            .map_err(|_| LogClientError::Unavailable(
                "BTV_LOG_VERIFYING_KEY not set — obtain from btv-sigma startup output".into()
            ))?;

        let key_bytes: [u8; 32] = hex::decode(&key_hex)
            .map_err(|e| LogClientError::Unavailable(format!("Invalid hex key: {e}")))?  
            .try_into()
            .map_err(|_| LogClientError::Unavailable("Key must be exactly 32 bytes".into()))?;

        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| LogClientError::Unavailable(format!("Invalid Ed25519 key: {e}")))?;

        Ok(Self::new(endpoint, vk))
    }

    /// Submit a verdict hash to btv-sigma and receive a verified `InclusionReceipt`.
    ///
    /// Verifies the Ed25519 signature BEFORE constructing the receipt.
    /// If verification fails → `Err(InvalidSignature)` → no receipt → no delivery.
    /// This is the Case D defence from Paper 2.
    pub async fn submit_and_await(
        &self,
        verdict_hash: &[u8; 32],
    ) -> Result<InclusionReceipt, LogClientError> {
        let resp = self.http
            .post(format!("{}/append", self.endpoint))
            .json(&serde_json::json!({ "verdict_hash": verdict_hash }))
            .send().await
            .map_err(|e| LogClientError::Unavailable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(LogClientError::Http(format!("Status: {}", resp.status())));
        }

        let body: AppendResponseWire = resp.json().await
            .map_err(|e| LogClientError::Deserialise(e.to_string()))?;

        // Reconstruct the signed message: index(8) || root(32) || verdict_hash(32) || timestamp(8)
        let mut message = Vec::with_capacity(80);
        message.extend_from_slice(&body.index.to_le_bytes());
        message.extend_from_slice(&body.root);
        message.extend_from_slice(verdict_hash);
        message.extend_from_slice(&body.timestamp.to_le_bytes());

        let signature = Signature::from_bytes(&body.signature);
        self.verifying_key.verify(&message, &signature)
            .map_err(|_| LogClientError::InvalidSignature)?;

        // Signature valid — safe to construct the receipt (pub(crate) constructor)
        Ok(InclusionReceipt::new_verified(
            body.index,
            body.root,
            body.signature,
            body.timestamp,
        ))
    }
}

#[derive(serde::Deserialize)]
struct AppendResponseWire {
    index:     u64,
    root:      [u8; 32],
    #[serde(with = "btv_types::serde_bytes_64_pub")]
    signature: [u8; 64],
    timestamp: u64,
}
