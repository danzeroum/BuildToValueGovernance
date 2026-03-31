//! HMAC-SHA256 sealing — key loaded once from `BTV_HMAC_KEY` environment variable.
//!
//! Paper 1, Limitation L1: "The HMAC key should be read from BTV_HMAC_KEY."
//! The key is cached in a `OnceLock` so the env var is only read at first use.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

static HMAC_KEY: OnceLock<Vec<u8>> = OnceLock::new();

fn get_key() -> &'static [u8] {
    HMAC_KEY.get_or_init(|| {
        std::env::var("BTV_HMAC_KEY")
            .expect("BTV_HMAC_KEY environment variable must be set before using btv-core")
            .into_bytes()
    })
}

/// Compute an HMAC-SHA256 seal over `evidence_hash || decision_byte || explanation`.
pub(crate) fn compute_seal(
    evidence_hash: &[u8; 32],
    decision: &btv_types::Decision,
    explanation: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(get_key())
        .expect("HMAC accepts any key length");
    mac.update(evidence_hash);
    mac.update(&[*decision as u8]);
    mac.update(explanation);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality check for HMAC tags.
pub(crate) fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // XOR all bytes and check none differ — prevents early-exit timing leak
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
