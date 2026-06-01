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
