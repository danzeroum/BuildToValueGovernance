//! Supply Guard v1.1.0 — PROP-031 (Skill Provenance MAC)
//! Verifica proveniência de skills via BLAKE3 keyed-hash (MAC) + registry lookup.
//! BLAKE3 keyed_hash é um MAC criptográfico definido pela spec BLAKE3 (equivalente
//! a HMAC em segurança, porém mais rápido e sem dependência adicional).
//! ADR: substituição HMAC-SHA256 → BLAKE3-MAC documentada em docs/ADR-031b.md.
//!
//! Fail-secure: qualquer falha → Blocked.
//! Zero heap no hot path: operações em buffers de tamanho fixo na stack.

use crate::security::skill_registry::is_skill_allowed;

/// Resultado da verificação do Supply Guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupplyGuardResult {
    Allowed,
    Blocked(SupplyGuardReason),
}

/// Motivo do bloqueio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupplyGuardReason {
    InvalidMac,
    NotAllowed,
}

/// Computa BLAKE3 keyed-MAC do skill_hash.
/// key de comprimento variável → deriva chave de 32 bytes via BLAKE3 hash.
/// Zero heap: operações sobre arrays fixos.
fn compute_mac(skill_hash: &[u8; 32], key: &[u8]) -> [u8; 32] {
    let derived_key = *blake3::hash(key).as_bytes();
    *blake3::keyed_hash(&derived_key, skill_hash).as_bytes()
}

/// Comparação em tempo constante (anti-timing-attack).
/// Zero heap: opera sobre slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verifica skill via MAC + registry lookup.
/// Fail-secure: MAC inválido ou skill não permitida → Blocked.
pub fn verify_skill(
    skill_hash: &[u8; 32],
    mac_tag: &[u8; 32],
    mac_key: &[u8],
) -> SupplyGuardResult {
    let expected = compute_mac(skill_hash, mac_key);
    if !constant_time_eq(&expected, mac_tag) {
        return SupplyGuardResult::Blocked(SupplyGuardReason::InvalidMac);
    }
    if !is_skill_allowed(skill_hash) {
        return SupplyGuardResult::Blocked(SupplyGuardReason::NotAllowed);
    }
    SupplyGuardResult::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tag(hash: &[u8; 32], key: &[u8]) -> [u8; 32] {
        compute_mac(hash, key)
    }

    #[test]
    fn valid_mac_empty_registry_allows() {
        let skill_hash = [0x42u8; 32];
        let key = b"test-mac-key";
        let tag = make_tag(&skill_hash, key);
        assert_eq!(verify_skill(&skill_hash, &tag, key), SupplyGuardResult::Allowed);
    }

    #[test]
    fn invalid_mac_blocks() {
        let skill_hash = [0x42u8; 32];
        let bad_tag = [0xFFu8; 32];
        let result = verify_skill(&skill_hash, &bad_tag, b"key");
        assert_eq!(result, SupplyGuardResult::Blocked(SupplyGuardReason::InvalidMac));
    }

    #[test]
    fn different_key_blocks() {
        let skill_hash = [0x11u8; 32];
        let tag = make_tag(&skill_hash, b"correct-key");
        let result = verify_skill(&skill_hash, &tag, b"wrong-key");
        assert_eq!(result, SupplyGuardResult::Blocked(SupplyGuardReason::InvalidMac));
    }

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(&[0x01u8; 32], &[0x01u8; 32]));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(&[0x01u8; 32], &[0x02u8; 32]));
    }

    #[test]
    fn constant_time_eq_length_mismatch() {
        assert!(!constant_time_eq(&[0u8; 32], &[0u8; 31]));
    }

    #[test]
    fn empty_key_allowed() {
        let skill_hash = [0x00u8; 32];
        let tag = make_tag(&skill_hash, b"");
        assert_eq!(verify_skill(&skill_hash, &tag, b""), SupplyGuardResult::Allowed);
    }
}
