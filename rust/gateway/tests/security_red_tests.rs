//! RED tests for the security remediation plan (Passo 0).
//!
//! These encode BDD scenarios that assert the **post-fix** behaviour and are
//! expected to FAIL until the matching remediation step lands.
//!
//! - CRITICO-07 (Passo 6): an invalid `Authorization: Bearer ...` must NOT
//!   bypass the API-key layer. Today the Bearer branch calls `inner.call(req)`
//!   unconditionally, so a bogus token reaches the handler (no 401).
//! - MED-R05 (Passo 7): when JWT decode fails in `TenantExtractorService`, the
//!   request must be rejected with 401, not silently routed to the default tenant.
//! - CRITICO-10 (Passo 9): `warm_policies()` must be called in `main.rs` before
//!   `axum::serve`. Before the fix, the first request sees stale/default tenant
//!   state (cold-load latency or wrong fairness mode).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod security_red {
    use axum_test::TestServer;
    use serde_json::json;
    use std::sync::Arc;

    use btv_gateway::routes::create_router;
    use btv_gateway::state::AppState;

    /// Build a server with API-key auth ENABLED so the auth layer is active.
    fn protected_server() -> TestServer {
        // ApiKeyLayer::from_env() reads these at router-build time.
        std::env::set_var("BTV_API_KEYS", "btv_test_key_1");
        std::env::set_var("BTV_JWT_SECRET", "ci-test-jwt-secret-32bytes-padding!!");
        let state = Arc::new(AppState::new());
        let app = create_router(state);
        TestServer::new(app).unwrap()
    }

    /// CRITICO-07: a forged Bearer token must be rejected with 401, not bypassed.
    /// Fixed in Passo 6 — the API-key layer now validates the JWT.
    #[tokio::test]
    async fn forged_bearer_token_is_rejected() {
        let server = protected_server();
        let res = server
            .post("/v1/validate")
            .add_header("authorization", "Bearer totally-invalid-token")
            .json(&json!({ "input": "Hello world" }))
            .await;

        assert_eq!(
            res.status_code(),
            401,
            "forged Bearer token bypassed the API-key layer (CRITICO-07)"
        );
    }

    /// A valid API key must still be accepted (invariant — should already pass).
    #[tokio::test]
    async fn valid_api_key_is_accepted() {
        let server = protected_server();
        let res = server
            .post("/v1/validate")
            .add_header("x-api-key", "btv_test_key_1")
            .json(&json!({ "input": "Hello world" }))
            .await;

        assert_eq!(res.status_code(), 200, "valid API key should be accepted");
    }
}

/// CRITICO-09: gatekeeper and session_tracker must use tokio::sync::Mutex so
/// waiting tasks yield cooperatively rather than blocking the executor thread.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod critico_09_async_locks {
    use std::sync::{
        atomic::{AtomicU32, Ordering::Relaxed},
        Arc,
    };

    use btv_gateway::state::AppState;

    /// 50 concurrent tasks must all acquire the gatekeeper lock and complete
    /// without deadlock or executor starvation.
    ///
    /// On a `current_thread` runtime: `std::sync::Mutex::lock()` is NOT a
    /// `Future` (compile error with `.await`), and blocking on it would starve
    /// the single executor thread.  `tokio::sync::Mutex::lock().await` yields
    /// cooperatively — all 50 tasks complete.
    #[tokio::test(flavor = "current_thread")]
    async fn gatekeeper_lock_does_not_block_executor_under_concurrency() {
        let state = Arc::new(AppState::new());
        let done = Arc::new(AtomicU32::new(0));

        let tasks: Vec<_> = (0u128..50)
            .map(|i| {
                let state = Arc::clone(&state);
                let done = Arc::clone(&done);
                tokio::spawn(async move {
                    // tokio::sync::Mutex::lock() returns a Future → awaitable.
                    // std::sync::Mutex::lock() is NOT a Future → compile error here.
                    let mut gk = state.gatekeeper.lock().await;
                    let _ = gk.scan_for_evidence(
                        &format!("concurrent-scan-input-{i}"),
                        i,
                    );
                    drop(gk);
                    done.fetch_add(1, Relaxed);
                })
            })
            .collect();

        for task in tasks {
            task.await.expect("task panicked (CRITICO-09 gatekeeper)");
        }

        assert_eq!(
            done.load(Relaxed),
            50,
            "CRITICO-09: all 50 concurrent gatekeeper accesses must complete"
        );
    }

    /// session_tracker must also use tokio::sync::Mutex.
    /// Each task produces its own TechnicalEvidence (via gatekeeper scan) and
    /// then calls session_tracker.track() — both locks are exercised concurrently.
    #[tokio::test(flavor = "current_thread")]
    async fn session_tracker_lock_does_not_block_executor_under_concurrency() {
        use buildtovalue_kernel::session_guard::DriftLevel;

        let state = Arc::new(AppState::new());
        let done = Arc::new(AtomicU32::new(0));

        let tasks: Vec<_> = (1u128..=50)
            .map(|i| {
                let state = Arc::clone(&state);
                let done = Arc::clone(&done);
                tokio::spawn(async move {
                    // Produce fresh evidence inside the task (TechnicalEvidence: !Clone).
                    let evidence = {
                        let mut gk = state.gatekeeper.lock().await;
                        gk.scan_for_evidence(&format!("tracker-input-{i}"), i)
                    };
                    let mut tracker = state.session_tracker.lock().await;
                    let result = tracker.track(i, &evidence);
                    let _ = match result.level {
                        DriftLevel::None | DriftLevel::Low => "low",
                        DriftLevel::Medium => "medium",
                        DriftLevel::High | DriftLevel::Critical => "high",
                    };
                    drop(tracker);
                    done.fetch_add(1, Relaxed);
                })
            })
            .collect();

        for task in tasks {
            task.await.expect("task panicked (CRITICO-09 session_tracker)");
        }

        assert_eq!(
            done.load(Relaxed),
            50,
            "CRITICO-09: all 50 concurrent session_tracker accesses must complete"
        );
    }
}

/// MED-R05: TenantExtractorService in isolation — malformed Bearer must yield
/// 401 rather than falling through to the default tenant (cross-tenant risk).
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod med_r05_tenant_extractor {
    use axum::{routing::get, Router};
    use axum_test::TestServer;
    use btv_gateway::middleware::tenant_extractor::{TenantExtractorLayer, TenantId};
    use axum::Extension;

    /// Minimal handler that echoes the resolved tenant_id.
    async fn echo_tenant(Extension(tid): Extension<TenantId>) -> String {
        tid.as_str().to_string()
    }

    /// Build a server wrapped ONLY with TenantExtractorLayer (no ApiKeyLayer).
    /// This tests MED-R05 defence-in-depth: the extractor must reject bad tokens
    /// independently of the upstream auth layer.
    fn tenant_extractor_only_server() -> TestServer {
        std::env::set_var("BTV_JWT_SECRET", "med-r05-test-secret-32bytes-padding");
        let app = Router::new()
            .route("/probe", get(echo_tenant))
            .layer(TenantExtractorLayer::from_env());
        TestServer::new(app).unwrap()
    }

    /// MED-R05 BDD scenario: "Bearer inválido → 401 em vez de roteado para `default`".
    /// Before the fix this returns 200 (with tenant_id = "default").
    /// After the fix it must return 401.
    #[tokio::test]
    async fn malformed_bearer_rejected_not_routed_to_default() {
        let server = tenant_extractor_only_server();
        let res = server
            .get("/probe")
            .add_header("authorization", "Bearer not-a-valid-jwt")
            .await;
        assert_eq!(
            res.status_code(),
            401,
            "MED-R05: malformed Bearer must be rejected with 401, not silently routed to default tenant"
        );
    }

    /// Regression: absence of Bearer must still succeed (anonymous → default tenant).
    #[tokio::test]
    async fn no_bearer_anonymous_request_allowed() {
        let server = tenant_extractor_only_server();
        let res = server.get("/probe").await;
        assert_eq!(
            res.status_code(),
            200,
            "request without Bearer should be accepted (anonymous → default tenant)"
        );
        assert_eq!(res.text(), "default", "anonymous request must use default tenant");
    }
}

/// CRITICO-10: startup contract — tenant policies must be loaded before the
/// server accepts its first request. `warm_policies` must be called in
/// `main.rs` BEFORE `axum::serve`.
///
/// The "RED" scenario is a cold-start gateway: without this call, a tenant
/// configured as Enforced on disk would appear as Disabled (the default) on
/// the first request, silently skipping fairness checks.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod critico_10_warm_policies {
    use std::sync::Arc;
    use tempfile::TempDir;

    use btv_gateway::fairness_mode::FairnessMode;
    use btv_gateway::policy_loader::warm_policies;
    use btv_gateway::state::AppState;
    use btv_gateway::tenant_status::TenantStatus;

    const BASELINE_YAML: &str = r#"
version: "1.0.0"
model_id: "startup-test"
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

    fn setup_tenant(root: &std::path::Path, id: &str, mode: &str, baseline: bool) {
        let dir = root.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fairness.yaml"), format!("mode: {mode}\n")).unwrap();
        if baseline {
            std::fs::write(dir.join("drift_baseline.yaml"), BASELINE_YAML).unwrap();
        }
    }

    /// BDD "fluxo 7": after startup warm, tenant state is loaded from disk
    /// before the first request. Without `warm_policies()`, `fairness_mode_for`
    /// returns Disabled (the registry default) even for Enforced tenants.
    #[tokio::test]
    async fn tenant_policy_loaded_before_first_request() {
        let tmp = TempDir::new().unwrap();
        setup_tenant(tmp.path(), "acme", "enforced", true);
        setup_tenant(tmp.path(), "legacy", "disabled", false);

        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));

        // Before warm_policies: acme looks Disabled (registry default).
        assert_eq!(
            state.fairness_mode_for("acme"),
            FairnessMode::Disabled,
            "CRITICO-10 pre-condition: before warm, acme must be Disabled (not yet loaded)"
        );

        // CRITICO-10 fix: this call must happen in main.rs before axum::serve.
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;

        // After warm_policies: acme is Enforced, legacy is Disabled, both Active.
        assert_eq!(
            state.fairness_mode_for("acme"),
            FairnessMode::Enforced,
            "CRITICO-10: acme must be Enforced after warm_policies"
        );
        assert_eq!(
            state.fairness_mode_for("legacy"),
            FairnessMode::Disabled,
            "CRITICO-10: legacy must be Disabled (config file)"
        );
        assert_eq!(
            state.tenant_statuses.status_for("acme"),
            TenantStatus::Active,
            "CRITICO-10: acme must be Active after warm_policies"
        );
    }

    /// Regression: gateway must still start cleanly with no policies_dir
    /// (dev environment with no tenants configured yet).
    #[tokio::test]
    async fn empty_policies_dir_does_not_block_startup() {
        let tmp = TempDir::new().unwrap();
        let state = Arc::new(AppState::with_policies_dir(tmp.path().to_path_buf()));

        // warm_policies with empty dir must not panic or return error.
        warm_policies(
            &state.policies_dir,
            &state.jonas_monitor,
            &state.fairness_modes,
            &state.tenant_statuses,
        )
        .await;

        assert_eq!(
            state.fairness_modes.declared_tenant_count(),
            0,
            "no tenants loaded from empty dir"
        );
    }
}
