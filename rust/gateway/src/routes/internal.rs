//! Endpoints internos do gateway (ADR-0089 §D2).
//!
//! - `POST /internal/v1/reload-policy/{tenant_id}` — recarrega
//!   `fairness.yaml` + `drift_baseline.yaml` do filesystem para um
//!   tenant. Idempotente (substitui entries existentes).
//! - `DELETE /internal/v1/tenants/{tenant_id}` — eager cleanup em 5
//!   componentes (TenantStorageRouter, Jonas, Rawls, FairnessModeRegistry,
//!   TenantStatusRegistry). Idempotente.
//!
//! Autenticação: `InternalAuthLayer` aplicado ao sub-router (Layer Tower
//! antes do despacho). Header `X-BTV-Internal-Key` em tempo constante.
//!
//! Despacho **estático** (decisão D5 ADR-0089): chama `state.rawls_monitor`
//! e `state.jonas_monitor` diretamente. Número de motores é fixo em
//! compile time — não há benefício de `dyn ReloadableGuardrail` para
//! dois receptores conhecidos. Reservar despacho dinâmico para quando
//! houver plugins de terceiros (ADR futuro).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use buildtovalue_kernel::security::tenant_key::validate_tenant_id;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::policy_loader::load_tenant_policy;
use crate::state::{AppState, EvictionReport};

/// Resposta do POST reload-policy. `status` carrega a tag JSON do
/// `TenantStatus` (state=active|initializing|degraded com cause).
#[derive(Debug, Serialize, Deserialize)]
pub struct ReloadResponse {
    pub tenant_id: String,
    pub status: crate::tenant_status::TenantStatus,
    pub fairness_mode: crate::fairness_mode::FairnessMode,
}

/// Resposta do DELETE eviction. Indica o que foi removido em cada
/// componente; o caller pode usar isso para auditoria.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvictResponse {
    pub tenant_id: String,
    pub evicted: EvictionReport,
}

/// POST /internal/v1/reload-policy/:tenant_id
pub async fn reload_policy_handler(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<ReloadResponse>, StatusCode> {
    // Validação prévia evita filesystem access para tenant_id inválido.
    if validate_tenant_id(&tenant_id).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    state.tenant_statuses.mark_initializing(&tenant_id);

    let dir = state.policies_dir.join(&tenant_id);
    if !dir.is_dir() {
        // Não há diretório → tenant não declarado em policies/.
        // Mantemos status anterior, mas sinalizamos via 404 ao caller.
        state.tenant_statuses.remove(&tenant_id);
        return Err(StatusCode::NOT_FOUND);
    }

    let result = load_tenant_policy(&dir, &tenant_id, &state.jonas_monitor).await;
    state.fairness_modes.install(&tenant_id, result.fairness_mode);
    state.tenant_statuses.set(&tenant_id, result.status.clone());

    Ok(Json(ReloadResponse {
        tenant_id: result.tenant_id,
        status: result.status,
        fairness_mode: result.fairness_mode,
    }))
}

/// DELETE /internal/v1/tenants/:tenant_id
pub async fn evict_tenant_handler(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<EvictResponse>, StatusCode> {
    if validate_tenant_id(&tenant_id).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let evicted = state.evict_tenant(&tenant_id).await;
    Ok(Json(EvictResponse {
        tenant_id,
        evicted,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fairness_mode::FairnessMode;
    use crate::middleware::internal_auth::InternalAuthLayer;
    use crate::tenant_status::TenantStatus;
    use axum::routing::{delete, post};
    use axum::Router;
    use axum_test::TestServer;
    use std::sync::Arc;
    use tempfile::TempDir;

    const VALID_BASELINE_YAML: &str = r#"
version: "1.0.0"
model_id: "test-model"
bins: 10
reference_proportions:
  - 0.05
  - 0.07
  - 0.10
  - 0.13
  - 0.15
  - 0.18
  - 0.15
  - 0.10
  - 0.05
  - 0.02
"#;

    const TEST_KEY: &[u8] = b"a-32-byte-test-key-padded-padded";

    fn build_app(state: Arc<AppState>) -> Router {
        let auth = InternalAuthLayer::with_key(TEST_KEY.to_vec());
        Router::new()
            .route(
                "/internal/v1/reload-policy/:tenant_id",
                post(reload_policy_handler),
            )
            .route(
                "/internal/v1/tenants/:tenant_id",
                delete(evict_tenant_handler),
            )
            .layer(auth)
            .with_state(state)
    }

    fn setup_tenant_files(tmp: &TempDir, tenant_id: &str, fairness: &str, baseline: Option<&str>) {
        let dir = tmp.path().join(tenant_id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fairness.yaml"), fairness).unwrap();
        if let Some(b) = baseline {
            std::fs::write(dir.join("drift_baseline.yaml"), b).unwrap();
        }
    }

    fn fresh_state() -> Arc<AppState> {
        Arc::new(AppState::new())
    }

    fn state_with_policies(tmp: &TempDir) -> Arc<AppState> {
        Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()))
    }

    fn auth_header() -> (axum::http::HeaderName, axum::http::HeaderValue) {
        (
            axum::http::HeaderName::from_static("x-btv-internal-key"),
            axum::http::HeaderValue::from_bytes(TEST_KEY).unwrap(),
        )
    }

    // ── Autenticação ──────────────────────────────────────────────

    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = fresh_state();
        let server = TestServer::new(build_app(state)).unwrap();
        let res = server.post("/internal/v1/reload-policy/acme").await;
        assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_auth_returns_401() {
        let state = fresh_state();
        let server = TestServer::new(build_app(state)).unwrap();
        let res = server
            .post("/internal/v1/reload-policy/acme")
            .add_header(
                axum::http::HeaderName::from_static("x-btv-internal-key"),
                axum::http::HeaderValue::from_static("wrong"),
            )
            .await;
        assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED);
    }

    // ── reload-policy ─────────────────────────────────────────────

    #[tokio::test]
    async fn reload_invalid_tenant_id_returns_400() {
        let state = fresh_state();
        let server = TestServer::new(build_app(state)).unwrap();
        let (k, v) = auth_header();
        let res = server
            .post("/internal/v1/reload-policy/UPPERCASE")
            .add_header(k, v)
            .await;
        assert_eq!(res.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn reload_missing_directory_returns_404() {
        let tmp = TempDir::new().unwrap();
        let state = state_with_policies(&tmp);
        let server = TestServer::new(build_app(state)).unwrap();
        let (k, v) = auth_header();
        let res = server
            .post("/internal/v1/reload-policy/ghost-tenant")
            .add_header(k, v)
            .await;
        assert_eq!(res.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn reload_enforced_with_baseline_returns_active() {
        let tmp = TempDir::new().unwrap();
        setup_tenant_files(&tmp, "acme", "mode: enforced\n", Some(VALID_BASELINE_YAML));
        let state = state_with_policies(&tmp);
        let server = TestServer::new(build_app(Arc::clone(&state))).unwrap();
        let (k, v) = auth_header();
        let res = server
            .post("/internal/v1/reload-policy/acme")
            .add_header(k, v)
            .await;
        res.assert_status_ok();
        let body: ReloadResponse = res.json();
        assert_eq!(body.tenant_id, "acme");
        assert_eq!(body.status, TenantStatus::Active);
        assert_eq!(body.fairness_mode, FairnessMode::Enforced);
        // Side-effects: registries atualizados.
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Enforced);
        assert_eq!(state.tenant_statuses.status_for("acme"), TenantStatus::Active);
    }

    #[tokio::test]
    async fn reload_enforced_without_baseline_returns_degraded_200() {
        let tmp = TempDir::new().unwrap();
        setup_tenant_files(&tmp, "acme", "mode: enforced\n", None);
        let state = state_with_policies(&tmp);
        let server = TestServer::new(build_app(Arc::clone(&state))).unwrap();
        let (k, v) = auth_header();
        let res = server
            .post("/internal/v1/reload-policy/acme")
            .add_header(k, v)
            .await;
        // 200 com status Degraded no body — operação completou, status
        // capturado para auditoria.
        res.assert_status_ok();
        let body: ReloadResponse = res.json();
        assert!(matches!(body.status, TenantStatus::Degraded { .. }));
    }

    // ── DELETE eviction ───────────────────────────────────────────

    #[tokio::test]
    async fn evict_invalid_tenant_returns_400() {
        let state = fresh_state();
        let server = TestServer::new(build_app(state)).unwrap();
        let (k, v) = auth_header();
        let res = server
            .delete("/internal/v1/tenants/UPPERCASE")
            .add_header(k, v)
            .await;
        assert_eq!(res.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn evict_ghost_tenant_returns_200_with_all_false() {
        let state = fresh_state();
        let server = TestServer::new(build_app(state)).unwrap();
        let (k, v) = auth_header();
        let res = server
            .delete("/internal/v1/tenants/never-existed")
            .add_header(k, v)
            .await;
        res.assert_status_ok();
        let body: EvictResponse = res.json();
        assert!(!body.evicted.any(), "ghost tenant não deve marcar nada como evicted");
    }

    #[tokio::test]
    async fn evict_after_reload_removes_all_components() {
        let tmp = TempDir::new().unwrap();
        setup_tenant_files(&tmp, "acme", "mode: shadow\n", Some(VALID_BASELINE_YAML));
        let state = state_with_policies(&tmp);
        let server = TestServer::new(build_app(Arc::clone(&state))).unwrap();
        let (k1, v1) = auth_header();
        let reload = server
            .post("/internal/v1/reload-policy/acme")
            .add_header(k1, v1)
            .await;
        reload.assert_status_ok();
        // Confirma que algo foi instalado.
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Shadow);

        let (k2, v2) = auth_header();
        let evict = server
            .delete("/internal/v1/tenants/acme")
            .add_header(k2, v2)
            .await;
        evict.assert_status_ok();
        let body: EvictResponse = res_json(&evict);
        // Jonas + fairness_modes + status devem ter sido removidos.
        assert!(body.evicted.jonas, "jonas baseline deve ser removido");
        assert!(body.evicted.fairness_mode, "fairness mode deve ser removido");
        assert!(body.evicted.status, "status deve ser removido");
        // Após evict, registries voltam a default.
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Disabled);
        assert_eq!(state.tenant_statuses.status_for("acme"), TenantStatus::Active);

        // Segunda eviction é idempotente (all false).
        let (k3, v3) = auth_header();
        let second = server
            .delete("/internal/v1/tenants/acme")
            .add_header(k3, v3)
            .await;
        let body2: EvictResponse = res_json(&second);
        assert!(!body2.evicted.any());
    }

    /// Helper para extrair JSON tipado de uma resposta `axum_test::TestResponse`
    /// quando a resposta já está consumida por `.json()` direto e queremos
    /// asserções customizadas.
    fn res_json<T: serde::de::DeserializeOwned>(res: &axum_test::TestResponse) -> T {
        res.json::<T>()
    }
}
