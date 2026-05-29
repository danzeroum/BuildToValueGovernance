//! audit-sink-local Commit 5 — End-to-end: `POST /v1/decide` emite um
//! `FairnessAuditEvent` que o drainer persiste como linha JSONL em
//! `{audit_dir}/{tenant_id}/events.jsonl`.
//!
//! Tenant usado: `"default"` (sem JWT) — middleware extrai e roteia.
//!
//! Disciplina anti-race: cada teste usa `AppState::with_audit_dir(tmp)`
//! com um `TempDir` próprio — sem env var compartilhada entre testes
//! paralelos. O drainer é assíncrono (MPSC + task), então aguardamos o
//! arquivo materializar com um pequeno poll antes de assertar.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum_test::TestServer;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    use btv_gateway::routes::create_router;
    use btv_gateway::state::AppState;

    fn server_from(state: Arc<AppState>) -> TestServer {
        let app = create_router(state);
        TestServer::new(app).unwrap()
    }

    /// Aguarda (poll com timeout) o JSONL do tenant aparecer e retorna seu
    /// conteúdo. O drainer roda em task separada; sem isto haveria flake.
    async fn await_jsonl(path: &std::path::Path) -> String {
        for _ in 0..50 {
            if let Ok(s) = std::fs::read_to_string(path) {
                if !s.trim().is_empty() {
                    return s;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        String::new()
    }

    #[tokio::test]
    async fn decide_emits_audit_jsonl_line() {
        let tmp = TempDir::new().unwrap();
        let state = Arc::new(AppState::with_audit_dir(tmp.path().to_path_buf()));
        let server = server_from(state);

        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "Hello world",
                "group_classification": "privileged",
                "decision_confidence": 0.85,
            }))
            .await;
        res.assert_status_ok();

        // Tenant default → arquivo em {audit_dir}/default/events.jsonl
        let events = tmp.path().join("default").join("events.jsonl");
        let content = await_jsonl(&events).await;
        assert!(
            !content.trim().is_empty(),
            "esperava ao menos uma linha JSONL de auditoria em {}",
            events.display()
        );

        // Cada linha é um FairnessAuditEvent serializado independente.
        let line = content.lines().next().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(parsed["schema_version"], "v1alpha");
        assert_eq!(parsed["tenant_id"], "default");
        assert!(
            parsed["verdict_id"].as_str().is_some(),
            "verdict_id deve ligar o evento ao ledger"
        );
        assert!(
            parsed["applied_action"].as_str().is_some(),
            "applied_action é a ação devolvida ao cliente"
        );
    }
}
