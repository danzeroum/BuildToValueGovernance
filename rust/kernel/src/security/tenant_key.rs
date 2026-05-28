//! Derivação de Tenant Encryption Key (TEK) via HKDF-SHA256 (ADR-0083).
//!
//! TEK = HKDF-SHA256(ikm=MKK, salt=[], info="btv-tek-v1:{tenant_id}", len=32)
//!
//! Invariantes:
//! - TEK retornada como `Zeroizing<[u8; 32]>` — apagada da memória ao sair do escopo.
//! - `tenant_id` validado (a-z 0-9 hífen, max 64 chars) antes de qualquer derivação.
//! - Nunca aloca TEK em `String` ou `Vec<u8>` não-zeroizing.

use ring::hkdf;
use zeroize::Zeroizing;

const HKDF_INFO_PREFIX: &[u8] = b"btv-tek-v1:";
const MAX_TENANT_ID_LEN: usize = 64;

/// Erro de derivação de chave de tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantKeyError {
    /// `tenant_id` contém caracteres fora de `[a-z0-9\-]` ou excede 64 chars.
    InvalidTenantId,
    /// Falha interna do HKDF (chave mestre inválida ou comprimento insupotado).
    HkdfFailure,
}

impl std::fmt::Display for TenantKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(
                f,
                "tenant_id must be 1–64 chars, only [a-z0-9-] allowed"
            ),
            Self::HkdfFailure => write!(f, "HKDF derivation failed (internal)"),
        }
    }
}

impl std::error::Error for TenantKeyError {}

/// Valida que `tenant_id` é seguro para uso como componente de path de filesystem
/// e como parâmetro de HKDF. Retorna `Err(InvalidTenantId)` se inválido.
pub fn validate_tenant_id(tenant_id: &str) -> Result<(), TenantKeyError> {
    if tenant_id.is_empty() || tenant_id.len() > MAX_TENANT_ID_LEN {
        return Err(TenantKeyError::InvalidTenantId);
    }
    if !tenant_id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(TenantKeyError::InvalidTenantId);
    }
    Ok(())
}

/// Deriva um TEK de 32 bytes a partir da Master Key e do `tenant_id`.
///
/// `master_key`: bytes da MKK (tipicamente de `keys::get_kernel_mac_key()`).
/// Retorna `Zeroizing<[u8; 32]>` — a chave é zerada ao ser descartada.
pub struct TenantKeyDeriver {
    /// PRK gerado via HKDF-Extract(salt=[], ikm=MKK).
    prk: hkdf::Prk,
}

impl TenantKeyDeriver {
    /// Constrói o deriver a partir dos bytes da MKK.
    /// `master_key` deve ter ≥ 16 bytes; valores menores resultam em chave fraca.
    pub fn new(master_key: &[u8]) -> Self {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(master_key);
        Self { prk }
    }

    /// Deriva TEK para o `tenant_id` dado.
    ///
    /// Retorna `Err(InvalidTenantId)` se o `tenant_id` não for `[a-z0-9\-]` (max 64).
    /// Retorna `Err(HkdfFailure)` em falha interna do HKDF (nunca deve ocorrer em uso
    /// normal — indica bug de configuração do caller).
    pub fn derive(&self, tenant_id: &str) -> Result<Zeroizing<[u8; 32]>, TenantKeyError> {
        validate_tenant_id(tenant_id)?;

        // info = "btv-tek-v1:{tenant_id}"
        let info_suffix = tenant_id.as_bytes();
        let info: &[&[u8]] = &[HKDF_INFO_PREFIX, info_suffix];

        let mut key_bytes = Zeroizing::new([0u8; 32]);
        self.prk
            .expand(info, MyLen(32))
            .and_then(|okm| okm.fill(key_bytes.as_mut()))
            .map_err(|_| TenantKeyError::HkdfFailure)?;

        Ok(key_bytes)
    }
}

/// Wrapper para indicar ao ring o comprimento da OKM desejada.
struct MyLen(usize);

impl hkdf::KeyType for MyLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn deriver() -> TenantKeyDeriver {
        TenantKeyDeriver::new(b"test-master-key-32-bytes-padding!")
    }

    #[test]
    fn valid_tenant_id_produces_32_byte_key() {
        let tek = deriver().derive("acme-corp").expect("derive");
        assert_eq!(tek.len(), 32);
    }

    #[test]
    fn different_tenants_produce_different_keys() {
        let d = deriver();
        let tek_a = d.derive("tenant-a").expect("a");
        let tek_b = d.derive("tenant-b").expect("b");
        assert_ne!(tek_a.as_ref(), tek_b.as_ref());
    }

    #[test]
    fn same_tenant_same_master_is_deterministic() {
        let d = deriver();
        let tek1 = d.derive("acme").expect("1");
        let tek2 = d.derive("acme").expect("2");
        assert_eq!(tek1.as_ref(), tek2.as_ref());
    }

    #[test]
    fn reject_uppercase() {
        assert_eq!(deriver().derive("AcmeCorp"), Err(TenantKeyError::InvalidTenantId));
    }

    #[test]
    fn reject_path_traversal() {
        assert_eq!(deriver().derive("../etc"), Err(TenantKeyError::InvalidTenantId));
        assert_eq!(deriver().derive("foo/bar"), Err(TenantKeyError::InvalidTenantId));
        assert_eq!(deriver().derive("foo bar"), Err(TenantKeyError::InvalidTenantId));
    }

    #[test]
    fn reject_empty_and_too_long() {
        assert_eq!(deriver().derive(""), Err(TenantKeyError::InvalidTenantId));
        let long = "a".repeat(65);
        assert_eq!(deriver().derive(&long), Err(TenantKeyError::InvalidTenantId));
    }

    #[test]
    fn accept_default_tenant() {
        deriver().derive("default").expect("default tenant must be valid");
    }

    #[test]
    fn validate_tenant_id_accepts_alphanumeric_and_hyphen() {
        assert!(validate_tenant_id("tenant-123").is_ok());
        assert!(validate_tenant_id("a").is_ok());
        assert!(validate_tenant_id("default").is_ok());
    }
}
