//! Kernel MAC key management — single source of truth (S-01).
//!
//! Replaces the hardcoded `KERNEL_MAC_KEY` literal previously inlined in
//! `gatekeeper.rs:34`. The key is now loaded once at startup from the
//! `BTV_HMAC_KEY` environment variable, stored in a `Zeroizing<Vec<u8>>`
//! singleton, and exposed through a single accessor.
//!
//! Fail-closed: in `BTV_ENV=production` the kernel refuses to start if the
//! env var is missing or matches a known development sentinel.
//!
//! Wire-up: call `init_kernel_mac_key()` in the gateway `main()` BEFORE any
//! pre-fork worker spawn. After init, the raw env var is removed from the
//! process environment to mitigate `/proc/self/environ` inspection.

use std::sync::OnceLock;
use zeroize::Zeroizing;

const DEV_FALLBACK: &[u8] = b"btv-kernel-supply-guard-v1";

const INSECURE_MARKERS: &[&str] = &[
    "NOT-FOR-PRODUCTION",
    "demo-key",
    "btv-dev-key",
    "btv-policy-engine-v1",
    "btv-verdict-hmac-v1",
    "btv-kernel-supply-guard",
];

static KERNEL_MAC_KEY: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();

#[derive(Debug)]
pub enum KeyInitError {
    MissingInProduction,
    InsecureSentinelInProduction(String),
    AlreadyInitialized,
}

impl std::fmt::Display for KeyInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingInProduction => write!(
                f,
                "BTV_HMAC_KEY must be set in production. Generate with: \
                 `openssl rand -hex 32`"
            ),
            Self::InsecureSentinelInProduction(marker) => write!(
                f,
                "BTV_HMAC_KEY contains a development sentinel ({marker}) and \
                 is unsafe for production use"
            ),
            Self::AlreadyInitialized => write!(
                f,
                "init_kernel_mac_key() was already called; use rotate_kernel_mac_key()"
            ),
        }
    }
}

impl std::error::Error for KeyInitError {}

fn is_insecure(s: &str) -> Option<&'static str> {
    INSECURE_MARKERS
        .iter()
        .find(|m| s.contains(*m))
        .copied()
}

fn resolve() -> Result<Zeroizing<Vec<u8>>, KeyInitError> {
    let env = std::env::var("BTV_ENV").unwrap_or_else(|_| "development".to_string());
    let raw = std::env::var("BTV_HMAC_KEY").ok();

    if env.eq_ignore_ascii_case("production") {
        let key = raw.ok_or(KeyInitError::MissingInProduction)?;
        if let Some(marker) = is_insecure(&key) {
            return Err(KeyInitError::InsecureSentinelInProduction(marker.to_string()));
        }
        return Ok(Zeroizing::new(key.into_bytes()));
    }

    if let Some(key) = raw {
        return Ok(Zeroizing::new(key.into_bytes()));
    }

    log::warn!(
        "BTV_HMAC_KEY not set; kernel using insecure dev fallback. \
         Set BTV_HMAC_KEY before deploying."
    );
    Ok(Zeroizing::new(DEV_FALLBACK.to_vec()))
}

/// Initialize the kernel MAC key. Call once at startup before any worker fork.
///
/// After successful init, `BTV_HMAC_KEY` is removed from the process
/// environment to reduce the attack surface of `/proc/self/environ`.
pub fn init_kernel_mac_key() -> Result<(), KeyInitError> {
    let resolved = resolve()?;
    KERNEL_MAC_KEY
        .set(resolved)
        .map_err(|_| KeyInitError::AlreadyInitialized)?;
    // Defense in depth: scrub from environ after consumption.
    // Safety: std::env operations are documented as not thread-safe in the
    // presence of getenv calls in C code; this must happen before workers spawn.
    std::env::remove_var("BTV_HMAC_KEY");
    Ok(())
}

/// Return a borrowed slice over the kernel MAC key.
///
/// Panics if `init_kernel_mac_key()` was not called — this is a programmer
/// error, not a runtime condition. Wire the init in the gateway `main()`.
///
/// `expect_used` is intentionally allowed here: silent fallback to a dev key
/// would be a security regression worse than a fail-loud panic. The gateway
/// initializes the key in `main()` before serving any request, and tests
/// that exercise this code path call `init_kernel_mac_key()` in their setup.
#[must_use]
#[allow(clippy::expect_used)]
pub fn kernel_mac_key() -> &'static [u8] {
    KERNEL_MAC_KEY
        .get()
        .expect(
            "init_kernel_mac_key() must be called in main() before the first \
             scan_for_evidence(). See rust/kernel/src/keys.rs.",
        )
        .as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_marker_detection() {
        assert!(is_insecure("btv-dev-key-NOT-FOR-PRODUCTION!!").is_some());
        assert!(is_insecure("demo-key-NOT-for-production-!!!!!").is_some());
        assert!(is_insecure("btv-kernel-supply-guard-v1").is_some());
        assert!(is_insecure("a1b2c3d4e5f6").is_none());
    }
}
