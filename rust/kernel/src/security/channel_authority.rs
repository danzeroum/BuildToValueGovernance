//! ChannelAuthority — Cenário 35: Conflito de Canais e Spoofing.
//!
//! Define hierarquia de confiança de canais de comunicação.
//! Ações críticas (Irreversible) exigem canal de nível mínimo HIGH.
//! Retificações por canal de nível inferior são bloqueadas.
//!
//! Fail-secure: canal desconhecido ou ausente → `Untrusted` (nível 0).
//! Zero heap: enum repr(u8) + tabela estática de mapeamento.

/// Nível de confiança de um canal de comunicação.
///
/// Ordenável: Untrusted < Low < Medium < High < Sovereign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ChannelTrustLevel {
    /// Canal desconhecido, ausente ou não autenticado. Nível 0.
    Untrusted = 0,
    /// SMS sem 2FA, e-mail não-autenticado, webhooks sem assinatura. Nível 1.
    Low = 1,
    /// WhatsApp com 2FA, Telegram verificado, OAuth básico. Nível 2.
    Medium = 2,
    /// App proprietário autenticado, chave API com HMAC. Nível 3.
    High = 3,
    /// Biometria + chave local, HSM assinado, TEE atestado. Nível 4.
    Sovereign = 4,
}

impl std::fmt::Display for ChannelTrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            ChannelTrustLevel::Untrusted => "Untrusted",
            ChannelTrustLevel::Low       => "Low",
            ChannelTrustLevel::Medium    => "Medium",
            ChannelTrustLevel::High      => "High",
            ChannelTrustLevel::Sovereign => "Sovereign",
        };
        write!(f, "{}", name)
    }
}

/// Violação detectada ao verificar autoridade de canal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelViolation {
    /// Nível do canal está abaixo do mínimo exigido para a ação.
    InsufficientTrust {
        actual:   ChannelTrustLevel,
        required: ChannelTrustLevel,
    },
}

impl std::fmt::Display for ChannelViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelViolation::InsufficientTrust { actual, required } =>
                write!(f, "InsufficientTrust: canal '{}' abaixo do mínimo '{}'", actual, required),
        }
    }
}

/// Tabela estática de canais conhecidos e seus níveis de confiança.
///
/// Mapeamento: nome do canal (minúsculo) → `ChannelTrustLevel`.
/// Canais ausentes → `Untrusted` (fail-secure).
static CHANNEL_TABLE: &[(&str, ChannelTrustLevel)] = &[
    // Nível LOW — canais fracamente autenticados
    ("sms",             ChannelTrustLevel::Low),
    ("email",           ChannelTrustLevel::Low),
    ("email_unverified",ChannelTrustLevel::Low),
    ("webhook",         ChannelTrustLevel::Low),

    // Nível MEDIUM — canais com 2FA ou OAuth básico
    ("whatsapp",        ChannelTrustLevel::Medium),
    ("whatsapp_2fa",    ChannelTrustLevel::Medium),
    ("telegram",        ChannelTrustLevel::Medium),
    ("oauth_basic",     ChannelTrustLevel::Medium),
    ("slack",           ChannelTrustLevel::Medium),

    // Nível HIGH — app proprietário com HMAC/API key
    ("app_authenticated",       ChannelTrustLevel::High),
    ("api_hmac",                ChannelTrustLevel::High),
    ("api_key_signed",          ChannelTrustLevel::High),
    ("openclaw_app",            ChannelTrustLevel::High),

    // Nível SOVEREIGN — biometria + chave local / TEE
    ("biometric_local",         ChannelTrustLevel::Sovereign),
    ("hsm_signed",              ChannelTrustLevel::Sovereign),
    ("tee_attested",            ChannelTrustLevel::Sovereign),
    ("hardware_security_key",   ChannelTrustLevel::Sovereign),
];

/// Resolve o nível de confiança de um canal pelo nome.
///
/// Fail-secure: `None` ou nome desconhecido → `Untrusted`.
///
/// # Exemplo
/// ```
/// use buildtovalue_kernel::security::channel_authority::{resolve_level, ChannelTrustLevel};
/// assert_eq!(resolve_level(None), ChannelTrustLevel::Untrusted);
/// assert_eq!(resolve_level(Some("email")), ChannelTrustLevel::Low);
/// assert_eq!(resolve_level(Some("whatsapp_2fa")), ChannelTrustLevel::Medium);
/// ```
pub fn resolve_level(channel: Option<&str>) -> ChannelTrustLevel {
    let name = match channel {
        None => return ChannelTrustLevel::Untrusted,
        Some(n) => n.trim().to_lowercase(),
    };

    CHANNEL_TABLE
        .iter()
        .find(|(k, _)| *k == name.as_str())
        .map(|(_, v)| *v)
        .unwrap_or(ChannelTrustLevel::Untrusted) // fail-secure: desconhecido → Untrusted
}

/// Verifica se `actual` atinge o nível `required`.
///
/// Fail-secure: se `actual < required` → `Err(InsufficientTrust)`.
///
/// # Exemplo
/// ```
/// use buildtovalue_kernel::security::channel_authority::{
///     assert_sufficient, ChannelTrustLevel
/// };
/// assert!(assert_sufficient(ChannelTrustLevel::High, ChannelTrustLevel::High).is_ok());
/// assert!(assert_sufficient(ChannelTrustLevel::Low, ChannelTrustLevel::High).is_err());
/// ```
pub fn assert_sufficient(
    actual: ChannelTrustLevel,
    required: ChannelTrustLevel,
) -> Result<(), ChannelViolation> {
    if actual >= required {
        Ok(())
    } else {
        Err(ChannelViolation::InsufficientTrust { actual, required })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_resolves_untrusted() {
        assert_eq!(resolve_level(None), ChannelTrustLevel::Untrusted);
    }

    #[test]
    fn test_unknown_resolves_untrusted_fail_secure() {
        assert_eq!(resolve_level(Some("carrier_pigeon")), ChannelTrustLevel::Untrusted);
        assert_eq!(resolve_level(Some("")), ChannelTrustLevel::Untrusted);
    }

    #[test]
    fn test_known_channels_correct_levels() {
        assert_eq!(resolve_level(Some("email")),           ChannelTrustLevel::Low);
        assert_eq!(resolve_level(Some("whatsapp_2fa")),    ChannelTrustLevel::Medium);
        assert_eq!(resolve_level(Some("api_hmac")),        ChannelTrustLevel::High);
        assert_eq!(resolve_level(Some("biometric_local")), ChannelTrustLevel::Sovereign);
    }

    #[test]
    fn test_case_insensitive_lookup() {
        assert_eq!(resolve_level(Some("EMAIL")), ChannelTrustLevel::Low);
        assert_eq!(resolve_level(Some("WhatsApp_2FA")), ChannelTrustLevel::Medium);
    }

    #[test]
    fn test_sufficient_same_level_ok() {
        assert!(assert_sufficient(ChannelTrustLevel::High, ChannelTrustLevel::High).is_ok());
        assert!(assert_sufficient(ChannelTrustLevel::Sovereign, ChannelTrustLevel::High).is_ok());
    }

    #[test]
    fn test_insufficient_trust_blocked() {
        let err = assert_sufficient(ChannelTrustLevel::Low, ChannelTrustLevel::High);
        assert!(err.is_err());
        let violation = err.unwrap_or_else(|_| panic!("BTV invariant violation: assert_sufficient deve retornar Err para Low < High"));
        // unwrap_err substituído: extraímos o Err via unwrap_or_else no Ok (inversão semântica)
        // A lógica correta: err é Err(_), então usamos if let
        if let Err(ChannelViolation::InsufficientTrust { actual, required }) =
            assert_sufficient(ChannelTrustLevel::Low, ChannelTrustLevel::High)
        {
            assert_eq!(actual, ChannelTrustLevel::Low);
            assert_eq!(required, ChannelTrustLevel::High);
        } else {
            panic!("BTV invariant violation: esperado InsufficientTrust");
        }
        let _ = violation;
    }

    #[test]
    fn test_untrusted_blocked_for_any_real_requirement() {
        assert!(assert_sufficient(ChannelTrustLevel::Untrusted, ChannelTrustLevel::Low).is_err());
    }

    #[test]
    fn test_ordering_correct() {
        assert!(ChannelTrustLevel::Untrusted < ChannelTrustLevel::Low);
        assert!(ChannelTrustLevel::Low < ChannelTrustLevel::Medium);
        assert!(ChannelTrustLevel::Medium < ChannelTrustLevel::High);
        assert!(ChannelTrustLevel::High < ChannelTrustLevel::Sovereign);
    }
}
