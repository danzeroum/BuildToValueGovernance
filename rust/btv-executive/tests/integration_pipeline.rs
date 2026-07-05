#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Critérios 2, 3, 4, 5: testes de integração do pipeline completo.
//!
//! Testes sem btv-sigma: verificam o pipeline até o ponto de log submission.
//! Testes COM btv-sigma: marcados `#[ignore]`, executados via CI service container.
#[cfg(test)]
mod pipeline_integration {
    use btv_core::{ComplianceAuthority, ComplianceRegistry, ComplianceError, LogClient};
    use btv_executive::{Executive, DecisionMaker, DecisionError, Decision};
    use ed25519_dalek::VerifyingKey;

    struct StubRegistry;
    impl ComplianceRegistry for StubRegistry {
        fn validate(&self, _j: &str, _p: &str) -> Result<u32, ComplianceError> { Ok(720) }
    }

    fn stub_auth() -> ComplianceAuthority {
        ComplianceAuthority::new(Box::new(StubRegistry))
    }

    fn dummy_key() -> VerifyingKey {
        // all-zeros Ed25519 point — valid (degenerate) for tests that don't reach the log
        VerifyingKey::from_bytes(&[0u8; 32]).expect("degenerate key")
    }

    fn make_no_log_exec() -> Executive {
        // btv-core exige BTV_HMAC_KEY em qualquer caminho que sela verdicts;
        // sem ela os testes falham por ambiente, não por comportamento.
        if std::env::var("BTV_HMAC_KEY").is_err() {
            std::env::set_var("BTV_HMAC_KEY", "integration-test-key");
        }
        // Port 19999 is not listening — log calls will fail as LogUnavailable
        Executive::new(
            stub_auth(),
            LogClient::new("http://127.0.0.1:19999".into(), dummy_key()),
            DecisionMaker::default_thresholds(),
        )
    }

    // ── Critério 4: input vazio → GatekeeperFailed (sem log needed) ───────────────

    #[tokio::test]
    async fn empty_input_returns_gatekeeper_failed() {
        let exec = make_no_log_exec();
        let err = exec.decide(b"", "BR", "LGPD-v1").await.unwrap_err();
        assert!(
            matches!(err, DecisionError::GatekeeperFailed(_)),
            "expected GatekeeperFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn oversized_input_returns_gatekeeper_failed() {
        let exec = make_no_log_exec();
        let big = vec![0x41u8; 66 * 1024]; // 66 KiB
        let err = exec.decide(&big, "BR", "LGPD-v1").await.unwrap_err();
        assert!(
            matches!(err, DecisionError::GatekeeperFailed(_)),
            "expected GatekeeperFailed for oversized input, got: {err}"
        );
    }

    // ── Critério 5: log indisponível → LogUnavailable (sem btv-sigma) ────────────
    //
    // Este teste não precisa de btv-sigma porque o log está em porta errada.
    // Valida que o pipeline falha no step 6 (submit) com LogUnavailable.

    #[tokio::test]
    async fn log_unavailable_returns_log_unavailable_error() {
        let exec = make_no_log_exec();
        // "hello" is clean — passes scan, gets a Verdict, then fails at log step
        let err = exec.decide(b"hello world", "BR", "LGPD-v1").await.unwrap_err();
        assert!(
            matches!(err, DecisionError::LogUnavailable(_)),
            "expected LogUnavailable when btv-sigma is not running, got: {err}"
        );
    }

    #[tokio::test]
    async fn deny_verdict_also_reaches_log_before_failing() {
        let exec = make_no_log_exec();
        // CPF input → Deny verdict → but log still not available → LogUnavailable
        // This proves the pipeline does NOT short-circuit on Deny
        let err = exec.decide(b"CPF: 123.456.789-09", "BR", "LGPD-v1").await.unwrap_err();
        assert!(
            matches!(err, DecisionError::LogUnavailable(_)),
            "Deny verdicts must still go through the log: {err}"
        );
    }

    // ── Critérios 2+3: pipeline completo (requer btv-sigma) ────────────────────────

    #[tokio::test]
    #[ignore = "requires btv-sigma on localhost:3100 with BTV_LOG_VERIFYING_KEY set"]
    async fn clean_input_allow_full_pipeline() {
        let exec = Executive::from_env(stub_auth())
            .expect("BTV_LOG_VERIFYING_KEY must be set");
        let result = exec.decide(b"Hello, normal message.", "BR", "LGPD-v1")
            .await
            .expect("full pipeline must succeed for clean input");
        assert_eq!(result.delivery.verdict.decision, Decision::Allow);
        assert!(result.decision_latency_us > 0);
    }

    #[tokio::test]
    #[ignore = "requires btv-sigma on localhost:3100 with BTV_LOG_VERIFYING_KEY set"]
    async fn cpf_input_deny_full_pipeline() {
        let exec = Executive::from_env(stub_auth())
            .expect("BTV_LOG_VERIFYING_KEY must be set");
        let result = exec.decide(b"CPF: 123.456.789-09", "BR", "LGPD-v1")
            .await
            .expect("CPF denial must still complete the full pipeline");
        assert_eq!(result.delivery.verdict.decision, Decision::Deny);
        // receipt proves it was logged
        assert!(result.delivery.receipt.timestamp > 0);
    }

    #[tokio::test]
    #[ignore = "requires btv-sigma on localhost:3100 with BTV_LOG_VERIFYING_KEY set"]
    async fn full_pipeline_latency_under_10ms() {
        let exec = Executive::from_env(stub_auth())
            .expect("BTV_LOG_VERIFYING_KEY must be set");
        let start = std::time::Instant::now();
        let result = exec.decide(b"Normal clean input.", "BR", "LGPD-v1")
            .await
            .expect("must succeed");
        let elapsed_ms = start.elapsed().as_millis();
        // Critério 11: p99 ≤ 10ms loopback
        assert!(elapsed_ms < 10,
            "pipeline p99 exceeded 10ms: got {}ms (critério 11)", elapsed_ms);
        // Also check via recorded latency
        assert!(result.decision_latency_us < 10_000,
            "decision_latency_us {} > 10ms", result.decision_latency_us);
    }
}
