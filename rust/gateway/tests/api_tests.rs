//! F1.9-04: Gateway API integration tests + benchmarks.

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use serde_json::json;
    use std::sync::Arc;

    // Import from gateway crate
    use btv_gateway::routes::create_router;
    use btv_gateway::state::AppState;

    fn test_server() -> TestServer {
        let state = Arc::new(AppState::new());
        let app = create_router(state);
        TestServer::new(app).unwrap()
    }

    // ─── HEALTH ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_health_endpoint() {
        let server = test_server();
        let res = server.get("/health").await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["status"], "ok");
        assert!(body["uptime_seconds"].as_u64().is_some());
    }

    // ─── VALIDATE ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_validate_clean_input() {
        let server = test_server();
        let res = server.post("/v1/validate")
            .json(&json!({ "input": "Hello world" }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["action"], "ALLOW");
        assert_eq!(body["finding_count"], 0);
        assert_eq!(body["contestable"], true);
    }

    #[tokio::test]
    async fn test_validate_cpf_detected() {
        let server = test_server();
        let res = server.post("/v1/validate")
            .json(&json!({ "input": "CPF: 123.456.789-09" }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["finding_count"].as_u64().unwrap() > 0);
        assert_eq!(body["appeal_deadline_hours"], 24);
    }

    #[tokio::test]
    async fn test_validate_empty_input() {
        let server = test_server();
        let res = server.post("/v1/validate")
            .json(&json!({ "input": "" }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["action"], "ALLOW");
    }

    // ─── METRICS ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let server = test_server();
        let res = server.get("/metrics").await;
        res.assert_status_ok();
    }

    // ─── POLICY TEST (Rawls Blind Review) ───────────────────────

    #[tokio::test]
    async fn test_policy_blind_review() {
        let policy = r#"
version: "1.0"
metadata:
  name: "Test"
  description: "Blind test"
  created_at: "2026-01-01"
  updated_at: "2026-01-01"
  author: "Test"
hard_blocks:
  - "DROP TABLE"
policies:
  - id: "block-cpf"
    name: "Block CPF"
    description: "Block CPF"
    enabled: true
    priority: 100
    conditions:
      validators: ["cpf"]
      min_severity: 0.5
      min_confidence: 0.9
    action: BLOCK
"#;

        let server = test_server();
        let res = server.post("/v1/policy/test")
            .json(&json!({
                "policy_yaml": policy,
                "test_inputs": [
                    { "input": "CPF: 123.456.789-09", "label": "cpf_direct" },
                    { "input": "Hello world", "label": "clean" },
                    { "input": "DROP TABLE users", "label": "sql_injection" },
                ]
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["blind_review"], true);
        assert_eq!(body["summary"]["total"], 3);
        assert!(body["summary"]["blocked"].as_u64().unwrap() >= 1);
    }

    // ─── LATENCY BENCHMARK ──────────────────────────────────────

    #[tokio::test]
    async fn test_validate_latency_under_50ms() {
        let server = test_server();

        // Warmup
        for _ in 0..5 {
            server.post("/v1/validate")
                .json(&json!({ "input": "CPF: 123.456.789-09" }))
                .await;
        }

        // Benchmark
        let iterations = 20;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            server.post("/v1/validate")
                .json(&json!({ "input": "CPF: 123.456.789-09" }))
                .await;
        }
        let avg_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;
        println!("Gateway avg latency: {avg_ms:.2f}ms");
        assert!(avg_ms < 50.0, "Avg {avg_ms:.2f}ms exceeds 50ms SLA");
    }
}