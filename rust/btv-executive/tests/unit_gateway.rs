//! Critério 11: endpoint HTTP `POST /v1/validate` e `/v1/decide`.
//!
//! Testa o roteador Axum com `tower::ServiceExt` sem iniciar servidor real.
//! Não requer btv-sigma.

#[cfg(test)]
mod gateway_unit {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `oneshot`
    use btv_executive::gateway::router;
    use btv_executive::{Executive, DecisionMaker};
    use btv_core::{ComplianceAuthority, ComplianceRegistry, ComplianceError};
    use std::sync::Arc;

    struct StubRegistry;
    impl ComplianceRegistry for StubRegistry {
        fn validate(&self, _j: &str, _p: &str) -> Result<u32, ComplianceError> { Ok(720) }
    }

    fn make_executive() -> Arc<Executive> {
        let authority = ComplianceAuthority::new(Box::new(StubRegistry));
        // Use a dummy LogClient pointing nowhere — it will fail at the log step,
        // which is expected for unit tests that only check routing + request parsing.
        let log_client = btv_core::LogClient::new(
            "http://127.0.0.1:19999".into(), // port not listening
            dummy_verifying_key(),
        );
        Arc::new(Executive::new(authority, log_client, DecisionMaker::default_thresholds()))
    }

    fn dummy_verifying_key() -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap()
    }

    #[tokio::test]
    async fn validate_endpoint_exists_and_accepts_json() {
        let app = router(make_executive());

        let body = serde_json::json!({
            "input": "hello",
            "jurisdiction": "BR",
            "policy_version": "LGPD-v1"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/validate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        // Even if the log is down, we get a 200 with status=blocked (not a 404/405)
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn decide_endpoint_exists_and_accepts_json() {
        let app = router(make_executive());

        let body = serde_json::json!({
            "input": "test",
            "jurisdiction": "BR",
            "policy_version": "LGPD-v1",
            "agent_id": "agent-001",
            "profile": "default"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/decide")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_blocked_response_has_no_delivery() {
        let app = router(make_executive());

        let body = serde_json::json!({
            "input": "hello",
            "jurisdiction": "BR",
            "policy_version": "LGPD-v1"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/validate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // When log is unavailable, status = "blocked" and delivery = null
        assert_eq!(json["status"], "blocked");
        assert!(json["delivery"].is_null(),
            "delivery must be null when blocked, got: {}", json["delivery"]);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let app = router(make_executive());

        let req = Request::builder()
            .method("GET")
            .uri("/v1/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
