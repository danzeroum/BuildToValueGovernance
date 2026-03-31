//! `EvidenceToken` — linear resource encoding the hash of a decision context.
//!
//! Paper 1, §3.1:
//! - Axiom 4.4 (contraction prohibited): no `Clone` or `Copy`
//! - Axiom 4.4 (weakening prohibited): `#[must_use]` prevents silent drops
//! - Axiom 4.5 protection B: `consume` is `pub(crate)` — external crates get E0624

use crate::hash::Blake3Hash;

/// A linear resource that irrevocably binds a BLAKE3 hash of the decision context.
///
/// Once created, this token can only be destroyed by passing it to `Verdict::new`.
/// Dropping it silently is a compile error due to `#[must_use]`.
#[must_use = "EvidenceToken must be consumed by Verdict::new — \
              dropping it silently is a silent decision (Paper 1, Case C)"]
pub struct EvidenceToken {
    hash: Blake3Hash,
}

impl EvidenceToken {
    /// Create a new evidence token, binding `context` irrevocably via BLAKE3.
    /// The hash is computed at construction and cannot be altered afterwards.
    pub fn new(context: &[u8]) -> Self {
        Self { hash: Blake3Hash::of(context) }
    }

    /// Consume the token, transferring its hash to the `Verdict` constructor.
    ///
    /// This is the UNIQUE destructor — `pub(crate)` means external code cannot
    /// call it (compile error E0624). Only `Verdict::new` can consume a token.
    pub(crate) fn consume(self) -> Blake3Hash {
        self.hash
    }
}

// Explicitly NOT implementing Clone, Copy, Default, or Drop.
// The absence of Clone is verified by compile-fail test `clone_evidence_token.rs`.
