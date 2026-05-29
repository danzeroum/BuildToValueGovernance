//! ADR-0091 — End-to-end do gRPC Audit Exposer.
//!
//! Sobe o servidor Tonic numa porta efêmera apontado para um `audit_dir`
//! temporário, escreve uma linha JSONL `FairnessAuditEvent`, conecta um
//! client gRPC e assere que o stream entrega o `FairnessDecision`
//! correspondente. Cobre também os caminhos de auth (chave válida/errada).
//!
//! `BTV_INTERNAL_SECRET` é setado para um valor fixo: o servidor lê o segredo
//! no boot via `internal_secret_from_env`. Todos os testes deste binário usam
//! o mesmo valor → sem race de env entre threads.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use btv_gateway::audit::grpc_exposer::pb;
    use btv_gateway::audit::grpc_exposer::pb::audit_exposer_client::AuditExposerClient;
    use btv_gateway::audit::grpc_exposer::serve_grpc_with_listener;
    use btv_gateway::audit::event::FairnessAuditEvent;
    use btv_gateway::fairness_mode::FairnessMode;
    use btv_gateway::tenant_status::TenantStatus;
    use tempfile::TempDir;
    use tonic::metadata::MetadataValue;
    use tonic::Request;

    const SECRET: &str = "test-internal-secret-key-32-bytes-minimum-aaa";

    /// Escreve um evento (append) e devolve seu `event_id` (UUID v7).
    fn write_event(audit_dir: &std::path::Path, tenant: &str, verdict: &str) -> String {
        let dir = audit_dir.join(tenant);
        std::fs::create_dir_all(&dir).unwrap();
        let mut e = FairnessAuditEvent::new(
            tenant.to_string(),
            verdict.to_string(),
            1_700_000_000_000,
            FairnessMode::Enforced,
            TenantStatus::Active,
        );
        e.applied_action = "REDACT".to_string();
        e.rawls_violation = true;
        let event_id = e.event_id.clone();
        let line = serde_json::to_string(&e).unwrap();
        let path = dir.join("events.jsonl");
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::write(&path, format!("{existing}{line}\n")).unwrap();
        event_id
    }

    /// Sobe o servidor numa porta efêmera; devolve o endpoint `http://...`.
    async fn spawn_server(audit_dir: std::path::PathBuf) -> String {
        std::env::set_var("BTV_INTERNAL_SECRET", SECRET);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_grpc_with_listener(audit_dir, listener).await;
        });
        // Dá um instante para o servidor começar a aceitar conexões.
        tokio::time::sleep(Duration::from_millis(100)).await;
        format!("http://{addr}")
    }

    fn with_key(req: &mut Request<pb::StreamRequest>, key: &str) {
        req.metadata_mut().insert(
            "x-btv-internal-key",
            MetadataValue::try_from(key).unwrap(),
        );
    }

    #[tokio::test]
    async fn streams_tailed_event_with_valid_key() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().to_path_buf();
        write_event(&audit_dir, "acme", "VRD-1");

        let endpoint = spawn_server(audit_dir).await;
        let mut client = AuditExposerClient::connect(endpoint).await.unwrap();

        let mut req = Request::new(pb::StreamRequest {
            tenant_id: "acme".to_string(),
            resume_after_event_id: String::new(),
        });
        with_key(&mut req, SECRET);

        let mut stream = client.stream_audit_events(req).await.unwrap().into_inner();

        // Aguarda a primeira mensagem com timeout (tail é poll-based).
        let msg = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout aguardando evento")
            .expect("erro no stream")
            .expect("stream encerrou sem evento");

        assert_eq!(msg.schema_version, "v1alpha");
        assert_eq!(msg.tenant_id, "acme");
        assert_eq!(msg.verdict_id, "VRD-1");
        assert_eq!(msg.applied_action, "REDACT");
        assert_eq!(msg.fairness_mode, "enforced");
        assert_eq!(msg.tenant_status, "active");
        assert!(msg.rawls_violation);
    }

    #[tokio::test]
    async fn wrong_key_is_unauthenticated() {
        let tmp = TempDir::new().unwrap();
        let endpoint = spawn_server(tmp.path().to_path_buf()).await;
        let mut client = AuditExposerClient::connect(endpoint).await.unwrap();

        let mut req = Request::new(pb::StreamRequest {
            tenant_id: "acme".to_string(),
            resume_after_event_id: String::new(),
        });
        with_key(&mut req, "wrong-key-which-is-also-32-bytes-long-xx");

        let err = client
            .stream_audit_events(req)
            .await
            .expect_err("esperava rejeição de auth");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn missing_key_is_unauthenticated() {
        let tmp = TempDir::new().unwrap();
        let endpoint = spawn_server(tmp.path().to_path_buf()).await;
        let mut client = AuditExposerClient::connect(endpoint).await.unwrap();

        // Sem metadata x-btv-internal-key.
        let req = Request::new(pb::StreamRequest {
            tenant_id: String::new(),
            resume_after_event_id: String::new(),
        });

        let err = client
            .stream_audit_events(req)
            .await
            .expect_err("esperava rejeição de auth");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn resume_after_event_id_skips_already_seen(/* ADR-0092 §D3 */) {
        // Dois eventos no JSONL; o cliente reconecta com o cursor = id do
        // primeiro → o stream deve entregar o SEGUNDO evento primeiro.
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().to_path_buf();
        let first_id = write_event(&audit_dir, "acme", "VRD-1");
        write_event(&audit_dir, "acme", "VRD-2");

        let endpoint = spawn_server(audit_dir).await;
        let mut client = AuditExposerClient::connect(endpoint).await.unwrap();

        let mut req = Request::new(pb::StreamRequest {
            tenant_id: "acme".to_string(),
            resume_after_event_id: first_id,
        });
        with_key(&mut req, SECRET);

        let mut stream = client.stream_audit_events(req).await.unwrap().into_inner();
        let msg = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout aguardando evento")
            .expect("erro no stream")
            .expect("stream encerrou sem evento");

        // Pula VRD-1 (já visto); primeiro evento entregue é VRD-2.
        assert_eq!(msg.verdict_id, "VRD-2", "cursor deve pular o evento já visto");
    }
}
