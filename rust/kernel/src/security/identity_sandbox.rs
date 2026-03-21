//! IdentitySandbox — Cenário 27: Contaminação de Contexto Cross-Profile.
//!
//! Verifica que o `agent_id` pertence exclusivamente ao perfil declarado,
//! impedindo que contextos de personas distintas se contaminem mutuamente.
//!
//! Algoritmo: XOR bitwise sobre [u8; 16] — zero heap, zero alocação.
//! Fail-secure: perfil ausente ou hash divergente → Err(SandboxViolation).

use std::collections::HashMap;

/// Tipo de violação detectada pelo sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxViolation {
    /// Hash do perfil da sessão diverge do hash registrado para este agente.
    ContextBleed,
    /// O `declared_profile` não existe no registry.
    ProfileMissing,
}

impl std::fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxViolation::ContextBleed  => write!(f, "ContextBleed: session profile hash mismatch"),
            SandboxViolation::ProfileMissing => write!(f, "ProfileMissing: declared profile not registered"),
        }
    }
}

/// Mapa imutável de perfis: nome → hash esperado ([u8; 16]).
///
/// Em produção, preencha via `ProfileRegistry::new()` na inicialização.
pub struct ProfileRegistry {
    profiles: HashMap<String, [u8; 16]>,
}

impl ProfileRegistry {
    /// Cria registry vazio.
    pub fn new() -> Self {
        Self { profiles: HashMap::new() }
    }

    /// Registra um perfil com seu hash canônico.
    pub fn register(&mut self, profile_name: &str, hash: [u8; 16]) {
        self.profiles.insert(profile_name.to_string(), hash);
    }

    /// Retorna o hash registrado para `profile_name`, ou `None` se ausente.
    pub fn get(&self, profile_name: &str) -> Option<&[u8; 16]> {
        self.profiles.get(profile_name)
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifica integridade de contexto: `agent_id` ⊕ `session_profile_hash`
/// deve ser zero quando ambos correspondem ao perfil declarado.
///
/// # Segurança
/// - Operação XOR bitwise: sem heap, sem ramificações sobre dados secretos.
/// - Fail-secure: qualquer ausência de registro → `Err(ProfileMissing)`.
///
/// # Exemplo
/// ```
/// use buildtovalue_kernel::security::identity_sandbox::{
///     assert_context_integrity, ProfileRegistry, SandboxViolation
/// };
/// let mut reg = ProfileRegistry::new();
/// let hash = [0u8; 16];
/// reg.register("work", hash);
/// let result = assert_context_integrity(&[0u8; 16], &hash, "work", &reg);
/// assert!(result.is_ok());
/// ```
pub fn assert_context_integrity(
    agent_id: &[u8; 16],
    session_profile_hash: &[u8; 16],
    declared_profile: &str,
    profile_registry: &ProfileRegistry,
) -> Result<(), SandboxViolation> {
    // Fail-secure: perfil não registrado → ProfileMissing
    let expected_hash = profile_registry
        .get(declared_profile)
        .ok_or(SandboxViolation::ProfileMissing)?;

    // XOR bitwise: se agent_id XOR session_profile_hash == expected_hash XOR session_profile_hash
    // simplifica para: agent_id == expected_hash (comparação constante via XOR)
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= agent_id[i] ^ expected_hash[i];
    }

    if diff != 0 {
        return Err(SandboxViolation::ContextBleed);
    }

    // Verifica também que session_profile_hash corresponde ao expected_hash
    let mut session_diff: u8 = 0;
    for i in 0..16 {
        session_diff |= session_profile_hash[i] ^ expected_hash[i];
    }

    if session_diff != 0 {
        return Err(SandboxViolation::ContextBleed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn make_registry() -> ProfileRegistry {
        let mut reg = ProfileRegistry::new();
        reg.register("work",    [0x01; 16]);
        reg.register("leisure", [0x02; 16]);
        reg
    }

    #[test]
    fn test_matching_profile_ok() {
        let reg = make_registry();
        let agent_id  = [0x01; 16];
        let sess_hash = [0x01; 16];
        assert!(assert_context_integrity(&agent_id, &sess_hash, "work", &reg).is_ok());
    }

    #[test]
    fn test_context_bleed_detected() {
        let reg = make_registry();
        let agent_id  = [0x02; 16]; // perfil "leisure"
        let sess_hash = [0x01; 16]; // hash de "work"
        let err = assert_context_integrity(&agent_id, &sess_hash, "work", &reg);
        assert_eq!(err, Err(SandboxViolation::ContextBleed));
    }

    #[test]
    fn test_profile_missing_fail_secure() {
        let reg = make_registry();
        let err = assert_context_integrity(&[0u8; 16], &[0u8; 16], "unknown", &reg);
        assert_eq!(err, Err(SandboxViolation::ProfileMissing));
    }

    #[test]
    fn test_session_hash_mismatch_bleed() {
        let reg = make_registry();
        let agent_id  = [0x01; 16]; // correto para "work"
        let sess_hash = [0x02; 16]; // divergente
        let err = assert_context_integrity(&agent_id, &sess_hash, "work", &reg);
        assert_eq!(err, Err(SandboxViolation::ContextBleed));
    }

    #[test]
    fn test_performance_under_500us() {
        let reg = make_registry();
        let agent_id  = [0x01; 16];
        let sess_hash = [0x01; 16];
        let start = Instant::now();
        let _r = assert_context_integrity(&agent_id, &sess_hash, "work", &reg);
        let elapsed = start.elapsed();
        assert!(elapsed.as_micros() < 500, "deve completar em <500µs: {:?}", elapsed);
    }
}
