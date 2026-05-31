//! RED tests for the security remediation plan (Passo 0).
//!
//! These encode BDD scenarios that assert the **post-fix** behaviour and are
//! expected to FAIL until the matching remediation step lands.
//!
//! - CRITICO-07 (Passo 6): an invalid `Authorization: Bearer ...` must NOT
//!   bypass the API-key layer. Today the Bearer branch calls `inner.call(req)`
//!   unconditionally, so a bogus token reaches the handler (no 401).

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
