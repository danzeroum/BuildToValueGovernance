//! Internal BLAKE3 hash — constructor is `pub(crate)` only.
//!
//! Axiom 4.5(3): "Construction of Blake3Hash via its tuple-struct field — the field is
//! private (E0423)." External crates cannot forge a hash; they can only observe the
//! wire format via `to_wire()`.

use btv_types::Blake3Hash as Blake3HashWire;

/// An internal BLAKE3 hash. The `inner` field is private — no external crate can
/// construct this type directly (compile error E0423).
pub struct Blake3Hash {
    inner: [u8; 32],
}

impl Blake3Hash {
    /// Only callable within `btv-core`. Computes BLAKE3 of `data`.
    pub(crate) fn of(data: &[u8]) -> Self {
        Self { inner: *blake3::hash(data).as_bytes() }
    }

    /// Convert to wire format for persistence/verification outside `btv-core`.
    pub fn to_wire(&self) -> Blake3HashWire {
        Blake3HashWire(self.inner)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

// Deliberately NOT implementing Clone, Copy, Default, PartialEq.
// Clone/Copy would allow contraction (Axiom 4.4 violation).
// PartialEq would enable comparison-based oracle attacks.
