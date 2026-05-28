//! `ReloadableGuardrail` trait — recarga e cleanup eager de tenant
//! (ADR-0089 §D2 + §D3).
//!
//! Contrato comum a `RawlsMonitor` e `JonasMonitor` para que endpoints
//! internos do gateway tratem-nos uniformemente:
//!
//! ```text
//! POST   /internal/v1/reload-policy/{tenant_id}  → reload_baseline
//! DELETE /internal/v1/tenants/{tenant_id}        → remove_tenant
//! ```
//!
//! **Invariante de storage-agnóstico:** `reload_baseline` recebe
//! `yaml_content: &str` — o kernel **nunca** toca filesystem. O gateway
//! é responsável por ler `policies/{tenant_id}/drift_baseline.yaml` e
//! passar o conteúdo. Isso permite que baseline venha de qualquer fonte
//! futura (gRPC, KMS-encrypted, signed payload) sem mudar o trait.
//!
//! **Idempotência:** `remove_tenant` em tenant inexistente é noop.

/// Erro de recarga. Mapeado para HTTP 4xx/5xx pelos handlers internos.
#[derive(Debug, Clone, PartialEq)]
pub enum ReloadError {
    /// Motor não aceita recarga via YAML (ex: `RawlsMonitor` cujo
    /// threshold é compile-time). Gateway trata como noop OK.
    NotApplicable,
    /// YAML malformado ou inválido pelo schema.
    InvalidYaml(String),
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplicable => write!(f, "motor não suporta reload via YAML"),
            Self::InvalidYaml(msg) => write!(f, "YAML inválido: {msg}"),
        }
    }
}

impl std::error::Error for ReloadError {}

/// Trait comum para motores fairness com lifecycle por tenant.
pub trait ReloadableGuardrail: Send + Sync {
    /// Recarrega o baseline/estado do tenant a partir de YAML.
    /// Retorna `Err(NotApplicable)` se este motor não tem baseline YAML
    /// (ex: Rawls). Gateway trata `NotApplicable` como noop OK.
    fn reload_baseline(&self, tenant_id: &str, yaml_content: &str) -> Result<(), ReloadError>;

    /// Remove todo o estado do tenant. Idempotente — tenant inexistente
    /// não causa erro. Retorna `true` se algo foi removido.
    fn remove_tenant(&self, tenant_id: &str) -> bool;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn reload_error_display_messages() {
        assert!(ReloadError::NotApplicable.to_string().contains("não suporta"));
        let err = ReloadError::InvalidYaml("missing field".to_string());
        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn reload_error_equality() {
        assert_eq!(ReloadError::NotApplicable, ReloadError::NotApplicable);
        assert_ne!(
            ReloadError::NotApplicable,
            ReloadError::InvalidYaml("x".into())
        );
    }

    // Mock impl para validar que trait é object-safe (dyn-compatible).
    struct MockMonitor;
    impl ReloadableGuardrail for MockMonitor {
        fn reload_baseline(&self, _: &str, _: &str) -> Result<(), ReloadError> {
            Err(ReloadError::NotApplicable)
        }
        fn remove_tenant(&self, _: &str) -> bool {
            false
        }
    }

    #[test]
    fn trait_is_object_safe() {
        // Se este código compila, o trait pode ser usado como
        // `&dyn ReloadableGuardrail` — necessário para endpoints internos
        // do gateway despacharem dinamicamente sobre Rawls/Jonas.
        let m: Box<dyn ReloadableGuardrail> = Box::new(MockMonitor);
        assert!(!m.remove_tenant("any"));
        assert!(matches!(
            m.reload_baseline("any", ""),
            Err(ReloadError::NotApplicable)
        ));
    }
}
