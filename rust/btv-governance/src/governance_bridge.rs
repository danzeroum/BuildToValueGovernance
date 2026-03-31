//! GovernanceBridge — publishes mandates and amendments to the Transparency Log
//! (Σ / btv-sigma).
//!
//! Paper 6, §3.5: "MandateToken is published in Σ at creation."
//!
//! **T3 invariant**: `btv-governance` never imports `btv-executive`.
//! The Executive reads `MandateWire` from Σ — the mandate flows through
//! the log, not through direct Rust imports.

use serde::Serialize;

use crate::{
    error::GovernanceError,
    mandate::MandateToken,
};

// ── Wire payload ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct MandatePublication<'a> {
    mandate_hash:        &'a [u8; 32],
    legislative_version: u64,
    expiry_utc:          i64,
    /// One of: "genesis" | "renewal" | "amendment"
    kind:                &'a str,
}

// ── GovernanceBridge ─────────────────────────────────────────────────────────

/// HTTP client that appends governance entries to btv-sigma.
pub struct GovernanceBridge {
    sigma_endpoint: String,
    http:           reqwest::Client,
}

impl GovernanceBridge {
    /// Construct with an explicit Σ endpoint URL.
    pub fn new(sigma_endpoint: String) -> Self {
        Self {
            sigma_endpoint,
            http: reqwest::Client::new(),
        }
    }

    /// Construct from the `BTV_SIGMA_ENDPOINT` environment variable.
    /// Falls back to `http://localhost:3100`.
    pub fn from_env() -> Self {
        let endpoint = std::env::var("BTV_SIGMA_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:3100".into());
        Self::new(endpoint)
    }

    /// Publish a `MandateToken` to Σ.
    ///
    /// `kind` must be one of: `"genesis"`, `"renewal"`, `"amendment"`.
    ///
    /// Returns the Σ log index assigned to this entry on success.
    pub async fn publish_mandate(
        &self,
        mandate: &MandateToken,
        kind: &str,
    ) -> Result<u64, GovernanceError> {
        let payload = MandatePublication {
            mandate_hash:        mandate.hash(),
            legislative_version: mandate.version(),
            expiry_utc:          mandate.expiry().timestamp(),
            kind,
        };

        let resp = self
            .http
            .post(format!("{}/append", self.sigma_endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| GovernanceError::LogPublicationFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(GovernanceError::LogPublicationFailed(format!(
                "Σ returned HTTP {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| GovernanceError::LogPublicationFailed(e.to_string()))?;

        Ok(body["index"].as_u64().unwrap_or(0))
    }
}
