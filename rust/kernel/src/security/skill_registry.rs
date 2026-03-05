//! Skill Provenance Registry v1.0.0 - PROP-031 (v1.5.2)
//! Zero heap no hot path: consulta HashSet estatico via lazy_static.

use lazy_static::lazy_static;
use std::collections::HashSet;

lazy_static! {
    static ref ALLOWED_HASHES: HashSet<[u8; 32]> = HashSet::new();
    static ref REVOKED_HASHES: HashSet<[u8; 32]> = HashSet::new();
}

/// Fail-secure: revogado -> false; registry vazio (dev) -> true.
/// Zero heap: lookup em HashSet estatico, sem alloc.
pub fn is_skill_allowed(hash: &[u8; 32]) -> bool {
    if REVOKED_HASHES.contains(hash) {
        return false;
    }
    if ALLOWED_HASHES.is_empty() {
        return true;
    }
    ALLOWED_HASHES.contains(hash)
}

pub fn registered_count() -> usize { ALLOWED_HASHES.len() }
pub fn revoked_count() -> usize { REVOKED_HASHES.len() }
