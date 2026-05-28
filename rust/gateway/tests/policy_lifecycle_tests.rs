//! ADR-0089 Commit 8 (consolidado em 6) — testes E2E do lifecycle de
//! policies: boot via filesystem real, reload via HTTP, evict via HTTP.
//!
//! Complementa os unit tests do `policy_loader` (que validam o walk em
//! memória) exercitando:
//!   1. `warm_policies()` consumindo `AppState.policies_dir` real
//!   2. Endpoint `POST /internal/v1/reload-policy/:tenant_id`
//!      sob autenticação `InternalAuthLayer`
//!   3. Endpoint `DELETE /internal/v1/tenants/:tenant_id`
//!   4. Roundtrip: install via filesystem → reload → evict → estado
//!      volta ao default
//!
//! Cada teste cria um `TempDir` próprio e usa
//! `AppState::with_policies_dir(tmp.path().to_path_buf())` — sem env
//! var, sem race entre testes paralelos.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum_test::TestServer;
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::TempDir;

    use axum::routing::{delete, post};
    use axum::Router;
    use btv_gateway::fairness_mode::FairnessMode;
    use btv_gateway::middleware::internal_auth::InternalAuthLayer;
    use btv_gateway::policy_loader::warm_policies;
    use btv_gateway::routes::internal::{
        evict_tenant_handler, reload_policy_handler, EvictResponse, ReloadResponse,
    };
    use btv_gateway::state::AppState;
    use btv_gateway::tenant_status::TenantStatus;

    const VALID_BASELINE_YAML: &str = r#"
version: "1.0.0"
model_id: "lifecycle-model"
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

    fn setup_tenant(root: &Path, tenant_id: &str, fairness: &str, baseline: Option<&str>) {
        let dir = root.join(tenant_id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fairness.yaml"), fairness).unwrap();
        if let Some(b) = baseline {
            std::fs::write(dir.join("drift_baseline.yaml"), b).unwrap();
        }
    }

    fn build_internal_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route(
                "/internal/v1/reload-policy/:tenant_id",
                post(reload_policy_handler),
            )
            .route(
                "/internal/v1/tenants/:tenant_id",
                delete(evict_tenant_handler),
            )
            .layer(InternalAuthLayer::with_key(TEST_KEY.to_vec()))
            .with_state(state)
    }

    fn auth_header() -> (axum::http::HeaderName, axum::http::HeaderValue) {
        (
            axum::http::HeaderName::from_static("x-btv-internal-key"),
            axum::http::HeaderValue::from_bytes(TEST_KEY).unwrap(),
        )
    }

    /// E2E 1: Boot via warm_policies + estado completo nos registries.
    #[tokio::test]
    async fn boot_with_filesystem_policies_installs_three_tenants() {
        let tmp = TempDir::new().unwrap();
        // Tenant 1: enforced + baseline → Active
        setup_tenant(tmp.path(), "acme", "mode: enforced\n", Some(VALID_BASELINE_YAML));
        // Tenant 2: shadow + baseline → Active
        setup_tenant(tmp.path(), "globex", "mode: shadow\n", Some(VALID_BASELINE_YAML));
        // Tenant 3: disabled (sem baseline) → Active sem Jonas
        setup_tenant(tmp.path(), "legacy", "mode: disabled\n", None);

        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));

        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;

        // Modes corretos por tenant.
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Enforced);
        assert_eq!(state.fairness_mode_for("globex"), FairnessMode::Shadow);
        assert_eq!(state.fairness_mode_for("legacy"), FairnessMode::Disabled);

        // Status Active para todos.
        assert_eq!(state.tenant_statuses.status_for("acme"), TenantStatus::Active);
        assert_eq!(state.tenant_statuses.status_for("globex"), TenantStatus::Active);
        assert_eq!(state.tenant_statuses.status_for("legacy"), TenantStatus::Active);

        // Jonas baseline instalado para acme e globex; record agora funciona.
        state.jonas_monitor.record("acme", 0.5, false);
        state.jonas_monitor.record("globex", 0.5, false);
        // Legacy não tem baseline — record é noop, sem panic.
        state.jonas_monitor.record("legacy", 0.5, false);
        assert!(state.jonas_monitor.metrics("legacy").is_none());
    }

    /// E2E 2: Tenant com baseline corrompido → Degraded, outros tenants
    /// ficam intactos (fault isolation).
    #[tokio::test]
    async fn boot_with_one_corrupted_baseline_isolates_failure() {
        let tmp = TempDir::new().unwrap();
        setup_tenant(tmp.path(), "good", "mode: enforced\n", Some(VALID_BASELINE_YAML));
        setup_tenant(tmp.path(), "broken", "mode: enforced\n", Some("::not yaml::"));

        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;

        assert_eq!(state.tenant_statuses.status_for("good"), TenantStatus::Active);
        assert!(matches!(
            state.tenant_statuses.status_for("broken"),
            TenantStatus::Degraded { .. }
        ));
        // good ainda funciona — baseline instalado.
        state.jonas_monitor.record("good", 0.5, false);
    }

    /// E2E 3: Reload via HTTP atualiza tenant existente.
    #[tokio::test]
    async fn reload_via_http_updates_existing_tenant() {
        let tmp = TempDir::new().unwrap();
        setup_tenant(tmp.path(), "acme", "mode: shadow\n", Some(VALID_BASELINE_YAML));

        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Shadow);

        // Edita fairness.yaml no filesystem antes do reload.
        let dir = tmp.path().join("acme");
        std::fs::write(dir.join("fairness.yaml"), "mode: enforced\n").unwrap();

        let server = TestServer::new(build_internal_router(Arc::clone(&state))).unwrap();
        let (k, v) = auth_header();
        let res = server
            .post("/internal/v1/reload-policy/acme")
            .add_header(k, v)
            .await;
        res.assert_status_ok();
        let body: ReloadResponse = res.json();
        assert_eq!(body.fairness_mode, FairnessMode::Enforced);
        assert_eq!(body.status, TenantStatus::Active);

        // Estado em memória reflete a mudança.
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Enforced);
    }

    /// E2E 4: Reload promove Degraded → Active após DPO corrigir o YAML
    /// na sequência boot-quebrado → fix-no-disco → reload.
    #[tokio::test]
    async fn reload_promotes_degraded_to_active_after_fix() {
        let tmp = TempDir::new().unwrap();
        setup_tenant(tmp.path(), "broken", "mode: enforced\n", Some("::not yaml::"));

        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;
        assert!(matches!(
            state.tenant_statuses.status_for("broken"),
            TenantStatus::Degraded { .. }
        ));

        // DPO corrige o baseline.
        let dir = tmp.path().join("broken");
        std::fs::write(dir.join("drift_baseline.yaml"), VALID_BASELINE_YAML).unwrap();

        let server = TestServer::new(build_internal_router(Arc::clone(&state))).unwrap();
        let (k, v) = auth_header();
        let res = server
            .post("/internal/v1/reload-policy/broken")
            .add_header(k, v)
            .await;
        res.assert_status_ok();
        let body: ReloadResponse = res.json();
        assert_eq!(body.status, TenantStatus::Active);
        assert_eq!(
            state.tenant_statuses.status_for("broken"),
            TenantStatus::Active
        );
    }

    /// E2E 5: Roundtrip completo — install via filesystem → evict via
    /// HTTP → estado volta ao default em todos os registries.
    #[tokio::test]
    async fn full_roundtrip_install_then_evict_resets_to_defaults() {
        let tmp = TempDir::new().unwrap();
        setup_tenant(tmp.path(), "acme", "mode: enforced\n", Some(VALID_BASELINE_YAML));

        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Enforced);

        let server = TestServer::new(build_internal_router(Arc::clone(&state))).unwrap();
        let (k, v) = auth_header();
        let res = server.delete("/internal/v1/tenants/acme").add_header(k, v).await;
        res.assert_status_ok();
        let body: EvictResponse = res.json();
        assert!(body.evicted.jonas, "jonas baseline removido");
        assert!(body.evicted.fairness_mode, "fairness mode removido");
        assert!(body.evicted.status, "status removido");

        // Defaults aplicáveis após eviction:
        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Disabled);
        assert_eq!(state.tenant_statuses.status_for("acme"), TenantStatus::Active);
        assert!(state.jonas_monitor.metrics("acme").is_none());
    }

    /// E2E 6: warm_policies é idempotente — segunda chamada reflete o
    /// estado atual do filesystem sem criar duplicatas.
    #[tokio::test]
    async fn warm_policies_idempotent_across_filesystem_changes() {
        let tmp = TempDir::new().unwrap();
        setup_tenant(tmp.path(), "acme", "mode: shadow\n", Some(VALID_BASELINE_YAML));

        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;

        // Atualiza fairness.yaml e re-warm.
        let dir = tmp.path().join("acme");
        std::fs::write(dir.join("fairness.yaml"), "mode: enforced\n").unwrap();
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;

        assert_eq!(state.fairness_mode_for("acme"), FairnessMode::Enforced);
        assert_eq!(state.fairness_modes.declared_tenant_count(), 1);
    }
}
