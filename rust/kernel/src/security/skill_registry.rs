//! Skill Provenance Registry v1.1.0 — PROP-031 / ADR-031b
//!
//! Zero heap no hot path: consulta slices estaticos gerados em build-time.
//! Os hashes sao compilados no binario via build.rs + skill_registry.yaml.
//!
//! Comportamento:
//!   registry vazio (allowed vazio) -> fail-open  (dev/staging, Jonas: gradual)
//!   registry nao-vazio             -> fail-secure (prod: hash ausente -> BLOCK)
//!   hash revogado                  -> BLOCK sempre (prioridade maxima)

// Inclui arrays gerados por build.rs a partir dos YAMLs
include!(concat!(env!("OUT_DIR"), "/skill_registry_generated.rs"));

/// Verifica se um skill hash e permitido.
///
/// Fail-secure: revogado -> false (prioridade maxima, sem excecao).
/// Fail-open:   allowed vazio -> true (dev sem registry configurado).
/// Zero heap:   lookup em slices estaticos — sem alloc no hot path.
#[inline]
pub fn is_skill_allowed(hash: &[u8; 32]) -> bool {
    // REVOKED tem prioridade absoluta (Jonas: responsabilidade preventiva)
    if REVOKED_SKILL_HASHES.contains(hash) {
        return false;
    }
    // Registry vazio = modo dev = fail-open (comportamento documentado)
    if ALLOWED_SKILL_HASHES.is_empty() {
        return true;
    }
    ALLOWED_SKILL_HASHES.contains(hash)
}

/// Numero de skills autorizadas compiladas no binario.
#[inline]
pub fn registered_count() -> usize {
    ALLOWED_SKILL_HASHES.len()
}

/// Numero de skills revogadas compiladas no binario.
#[inline]
pub fn revoked_count() -> usize {
    REVOKED_SKILL_HASHES.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowed_is_fail_open() {
        // Registry vazio (dev): qualquer hash nao-revogado e permitido
        if ALLOWED_SKILL_HASHES.is_empty() {
            let hash = [0u8; 32];
            assert!(is_skill_allowed(&hash), "registry vazio deve ser fail-open");
        }
    }

    #[test]
    fn revoked_always_blocked() {
        // Se ha hashes revogados, verificar que sao bloqueados
        for revoked_hash in REVOKED_SKILL_HASHES {
            assert!(
                !is_skill_allowed(revoked_hash),
                "hash revogado nao deve ser permitido: {:?}", revoked_hash
            );
        }
    }

    #[test]
    fn counts_are_consistent() {
        assert_eq!(registered_count(), ALLOWED_SKILL_HASHES.len());
        assert_eq!(revoked_count(), REVOKED_SKILL_HASHES.len());
    }
}
