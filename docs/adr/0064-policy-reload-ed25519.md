# ADR-064 — Policy Reload with Ed25519

**Status:** Accepted  
**Date:** 2026-05-19

## Context

If HMAC were used for policy signatures, the server verifying policies would
share the key with the Ethics Committee signing them. A compromised server
could forge policy YAML and inject arbitrary rules — a catastrophic
failure mode for a governance system.

## Decision

Policy YAMLs are signed with **Ed25519** (asymmetric):

- **Private key**: held exclusively by the Ethics Committee. Never on the
  server, never in git.
- **Public key**: on the server, used only for verification.

### Rust: `PolicyWatcher` in `kernel/src/policy/loader.rs`

```rust
pub struct PolicyWatcher { verifying_key: VerifyingKey }

impl PolicyWatcher {
    pub fn verify_and_load(&self, yaml_bytes: &[u8], sig_bytes: &[u8; 64])
        -> Result<Policy, PolicyLoadError>
}
```

Parsing occurs only after `ed25519_dalek::VerifyingKey::verify()` succeeds.
An invalid or missing signature returns `Err(PolicyLoadError::InvalidSignature)`
— the policy is never parsed, never applied.

### Python: `policy_loader.py` (pre-existing)

`load_ethics_committee_pubkey()` + `verify_policy_yaml()` implement the same
pattern using the `cryptography` library's `Ed25519PublicKey`. The Rust
`PolicyWatcher` provides the same guarantees for Rust callers without the
Python runtime.

### Dependency

`ed25519-dalek = { version = "2", features = ["std"] }` added to
`kernel/Cargo.toml` (already in workspace `Cargo.toml`).

## Key management

- Public key path: `BTV_POLICY_PUBKEY_PATH` env var (default:
  `data/keys/ethics_committee_pubkey.pem`).
- Key rotation: generate new keypair, deploy new public key via secrets
  management, re-sign all policies with new private key.
- The private key is **never** stored on any server and is not a secret in
  any CI/CD system.

## Consequences

- A compromised server cannot forge legislation.
- Unsigned or incorrectly signed policies are rejected before parsing,
  eliminating YAML injection as a policy-tampering vector.
- Policy updates require offline signing by the Ethics Committee — this
  is intentional (separation of powers, not a convenience limitation).
