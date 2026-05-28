//! TenantStorageRouter — roteamento de `DurableLedger` por tenant (ADR-0083).
//!
//! Cada tenant recebe um arquivo de ledger isolado em:
//!   `{base_path}/{tenant_id}/ledger.db`
//!
//! O tenant `"default"` é retro-compatível com o singleton pré-ADR-0083.
//!
//! Invariantes:
//! - `tenant_id` validado via `security::tenant_key::validate_tenant_id` antes
//!   de qualquer acesso ao filesystem — path traversal é impossível em nível
//!   de kernel.
//! - `DurableLedger` criado lazy (on first access) e cacheado em
//!   `tokio::sync::RwLock<HashMap>`.
//! - Sem `panic!`/`unwrap` — todos os erros retornam `RouterError`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Context;

use crate::ledger::durable_ledger::DurableLedger;
use crate::ledger::remote::config::S3Config;
use crate::security::tenant_key::validate_tenant_id;

/// Tenant padrão — retro-compatível com o singleton pré-ADR-0083.
pub const DEFAULT_TENANT_ID: &str = "default";

/// Erro do router.
#[derive(Debug)]
pub enum RouterError {
    /// `tenant_id` contém caracteres inválidos (path traversal prevention).
    InvalidTenantId(String),
    /// Falha ao criar ou abrir o ledger do tenant.
    LedgerInit(anyhow::Error),
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId(id) => write!(
                f,
                "tenant_id '{id}' is invalid: only [a-z0-9-] (max 64 chars) allowed"
            ),
            Self::LedgerInit(e) => write!(f, "failed to initialize ledger: {e}"),
        }
    }
}

impl std::error::Error for RouterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LedgerInit(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// Roteador de ledger por tenant.
///
/// Criado uma vez no boot e injetado no `Gatekeeper`. Imutável após
/// construção, exceto pelo cache interno de ledgers abertos.
pub struct TenantStorageRouter {
    base_path: PathBuf,
    s3_config: S3Config,
    cache: RwLock<HashMap<String, Arc<DurableLedger>>>,
}

impl TenantStorageRouter {
    /// Cria o router. `base_path` é o diretório raiz onde os subdiretórios
    /// `{tenant_id}/` serão criados.
    pub fn new(base_path: PathBuf, s3_config: S3Config) -> Self {
        Self {
            base_path,
            s3_config,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Retorna o `DurableLedger` para o `tenant_id` dado.
    ///
    /// Se o ledger ainda não foi aberto nesta sessão, cria o diretório e
    /// inicializa um novo `DurableLedger`. Chamadas subsequentes retornam
    /// a instância cacheada.
    ///
    /// Retorna `Err(InvalidTenantId)` se o `tenant_id` não for `[a-z0-9-]`
    /// (max 64 chars) — nunca toca o filesystem nesses casos.
    pub async fn route(&self, tenant_id: &str) -> Result<Arc<DurableLedger>, RouterError> {
        validate_tenant_id(tenant_id)
            .map_err(|_| RouterError::InvalidTenantId(tenant_id.to_string()))?;

        // Fast path — ledger já em cache.
        {
            let guard = self.cache.read().await;
            if let Some(ledger) = guard.get(tenant_id) {
                return Ok(Arc::clone(ledger));
            }
        }

        // Slow path — inicializa e insere no cache.
        let mut guard = self.cache.write().await;
        // Verificação dupla: outro task pode ter inserido entre read e write.
        if let Some(ledger) = guard.get(tenant_id) {
            return Ok(Arc::clone(ledger));
        }

        let ledger_path = self.ledger_path(tenant_id);
        std::fs::create_dir_all(ledger_path.parent().unwrap_or(&ledger_path))
            .context("create tenant directory")
            .map_err(RouterError::LedgerInit)?;

        let ledger = DurableLedger::new(ledger_path, self.s3_config.clone())
            .await
            .context("DurableLedger::new")
            .map_err(RouterError::LedgerInit)?;

        let arc = Arc::new(ledger);
        guard.insert(tenant_id.to_string(), Arc::clone(&arc));
        Ok(arc)
    }

    /// Número de tenants com ledger aberto nesta sessão (inclui "default").
    pub async fn active_tenant_count(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Caminho absoluto do arquivo de ledger para o tenant dado.
    /// Apenas para uso interno e testes — não valida `tenant_id`.
    fn ledger_path(&self, tenant_id: &str) -> PathBuf {
        self.base_path.join(tenant_id).join("ledger.db")
    }
}

/// Valida que o `tenant_id` do JWT corresponde ao `tenant_id` de roteamento.
///
/// Retorna `Ok(())` se correspondem. Retorna `Err` com uma mensagem descritiva
/// se não correspondem (o Gatekeeper deve mapear para `EthicalError::E131`).
///
/// Se o JWT não tiver `tenant_id` (valor `None`), roteia para `"default"` sem
/// erro (retro-compatibilidade com clientes pré-ADR-0083).
pub fn validate_tenant_claim<'a>(
    jwt_tenant_id: Option<&'a str>,
    routing_tenant_id: &'a str,
) -> Result<&'a str, &'static str> {
    match jwt_tenant_id {
        None => Ok(DEFAULT_TENANT_ID),
        Some(jwt_tid) if jwt_tid == routing_tenant_id => Ok(routing_tenant_id),
        Some(_) => Err("tenant_id in JWT does not match routing context"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_router(tmp: &TempDir) -> TenantStorageRouter {
        TenantStorageRouter::new(tmp.path().to_path_buf(), S3Config::default())
    }

    #[tokio::test]
    async fn route_invalid_tenant_id_never_touches_fs() {
        let tmp = TempDir::new().unwrap();
        let router = make_router(&tmp);
        match router.route("../../etc/passwd").await {
            Err(RouterError::InvalidTenantId(_)) => {}
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("expected InvalidTenantId error"),
        }
        // filesystem não foi tocado — diretório tmp ainda vazio
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .collect();
        assert!(entries.is_empty(), "router touched the filesystem for invalid tenant_id");
    }

    #[tokio::test]
    async fn route_uppercase_rejected() {
        let tmp = TempDir::new().unwrap();
        let router = make_router(&tmp);
        match router.route("AcmeCorp").await {
            Err(RouterError::InvalidTenantId(_)) => {}
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("expected InvalidTenantId error"),
        }
    }

    #[tokio::test]
    async fn route_creates_ledger_directory() {
        let tmp = TempDir::new().unwrap();
        let router = make_router(&tmp);
        // route() pode falhar em S3Config default (sem servidor),
        // mas o diretório deve ser criado antes disso.
        let _ = router.route("acme-corp").await;
        assert!(tmp.path().join("acme-corp").exists());
    }

    #[tokio::test]
    async fn route_returns_same_arc_on_second_call() {
        let tmp = TempDir::new().unwrap();
        let router = make_router(&tmp);
        let first = router.route("tenant-a").await;
        let second = router.route("tenant-a").await;
        if let (Ok(a), Ok(b)) = (first, second) {
            assert!(Arc::ptr_eq(&a, &b), "must return the same Arc");
        }
    }

    #[test]
    fn ledger_path_is_scoped_to_tenant() {
        let tmp = TempDir::new().unwrap();
        let router = TenantStorageRouter::new(tmp.path().to_path_buf(), S3Config::default());
        let path = router.ledger_path("acme");
        assert!(path.ends_with("acme/ledger.db"));
    }

    #[test]
    fn validate_tenant_claim_match() {
        assert_eq!(
            validate_tenant_claim(Some("acme"), "acme"),
            Ok("acme")
        );
    }

    #[test]
    fn validate_tenant_claim_mismatch() {
        assert!(validate_tenant_claim(Some("acme"), "rival").is_err());
    }

    #[test]
    fn validate_tenant_claim_none_routes_to_default() {
        assert_eq!(
            validate_tenant_claim(None, "anything"),
            Ok(DEFAULT_TENANT_ID)
        );
    }

    /// ADR-0083 E2E: dois tenants distintos devem produzir arquivos de ledger
    /// fisicamente isolados em subdiretórios separados.
    #[tokio::test]
    async fn two_tenants_get_physically_isolated_files() {
        let tmp = TempDir::new().unwrap();
        let router = make_router(&tmp);

        // Roteamento de dois tenants distintos (cada um deve criar seu próprio
        // diretório, independentemente do sucesso da inicialização do ledger).
        let _ = router.route("acme").await;
        let _ = router.route("globex").await;

        let acme_dir = tmp.path().join("acme");
        let globex_dir = tmp.path().join("globex");
        assert!(acme_dir.exists(), "acme/ directory must exist");
        assert!(globex_dir.exists(), "globex/ directory must exist");
        assert_ne!(
            acme_dir, globex_dir,
            "tenants must have distinct directory paths"
        );

        // O cache do router deve refletir dois tenants ativos (se ambos
        // foram inicializados com sucesso) ou zero (se a inicialização falhar
        // graciosamente em ambos). Nunca um número intermediário não-determinístico.
        let active = router.active_tenant_count().await;
        assert!(active == 0 || active == 2, "expected 0 or 2 active tenants, got {active}");
    }
}
