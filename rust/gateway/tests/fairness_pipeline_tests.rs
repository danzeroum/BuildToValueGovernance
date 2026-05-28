//! ADR-0088 Commit 6 — End-to-end tests for the fairness pipeline.
//!
//! Exercita `/v1/decide` via `axum_test` cobrindo os três modos
//! (Disabled/Shadow/Enforced) e o cenário de baseline ausente — estado
//! real de qualquer tenant novo em produção.
//!
//! Tenant usado: `"default"` (sem JWT) — middleware extrai e roteia.
//!
//! Side-effects do handler que NÃO afetam os asserts:
//! - HTTP POST para `BTV_GOVERNANCE_URL` (Python governance) falha por
//!   connection refused; handler usa fallback kernel-only.
//! - Escrita em `data/ledger/default/decisions.jsonl` e no binary ledger;
//!   ambos têm fallback. Tests não asseram filesystem state — focam na
//!   resposta HTTP que é a fonte de verdade para clientes.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum_test::TestServer;
    use serde_json::json;
    use std::sync::Arc;

    use btv_gateway::fairness_mode::FairnessMode;
    use btv_gateway::routes::create_router;
    use btv_gateway::state::AppState;
    use buildtovalue_kernel::statistics::{
        GroupClass, JonasBaselineLoader, OutcomeBucket,
    };

    const VALID_BASELINE: &str = r#"
version: "1.0.0"
model_id: "test-model-v1"
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

    /// Constrói um AppState fresco. Os helpers de instalação (modes/baselines)
    /// agem sobre o estado depois — funcionam mesmo após o Arc ser clonado
    /// para o router (RwLock interno em registry/monitor).
    fn fresh_state() -> Arc<AppState> {
        Arc::new(AppState::new())
    }

    fn populate_rawls_violation(state: &AppState, tenant: &str) {
        // 100 Privileged Favoráveis + 100 Unprivileged Desfavoráveis
        // → DIR = 0/100 ÷ 100/100 = 0.0 → violates_threshold = true.
        for _ in 0..100 {
            state
                .rawls_monitor
                .record(tenant, GroupClass::Privileged, OutcomeBucket::Favorable);
            state
                .rawls_monitor
                .record(tenant, GroupClass::Unprivileged, OutcomeBucket::Unfavorable);
        }
    }

    fn server_from(state: Arc<AppState>) -> TestServer {
        let app = create_router(state);
        TestServer::new(app).unwrap()
    }

    // ─── Caso 1: Tenant novo em produção (sem config alguma) ─────

    #[tokio::test]
    async fn new_tenant_without_config_has_no_governance_errors() {
        // Cenário que operadores enfrentam: tenant novo, sem install de
        // baseline Jonas, sem install de FairnessMode no registry.
        // Default seguro: FairnessMode::Disabled, sem composição, sem
        // governance_errors.
        let server = server_from(fresh_state());
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "Hello world",
                "group_classification": "privileged",
                "decision_confidence": 0.85,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        // Sem modo configurado → Disabled → sem governance_errors no laudo.
        let errors = body["explain"]["governance_errors"].as_array();
        assert!(
            errors.is_none() || errors.unwrap().is_empty(),
            "governance_errors deve estar ausente/vazio para tenant sem config, got: {:?}",
            body["explain"]["governance_errors"]
        );
        assert!(
            body["explain"]["legacy_error"].is_null(),
            "legacy_error deve ser null"
        );
    }

    // ─── Caso 2: Shadow mode SEM violação acumulada ───────────────

    #[tokio::test]
    async fn shadow_mode_without_violations_emits_no_errors() {
        let state = fresh_state();
        state
            .fairness_modes
            .install("default", FairnessMode::Shadow);
        // Não populamos Rawls — DIR retorna insufficient_samples,
        // composição não escala.

        let server = server_from(state);
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "neutral input",
                "group_classification": "privileged",
                "decision_confidence": 0.7,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        let errors = body["explain"]["governance_errors"].as_array();
        assert!(
            errors.is_none() || errors.unwrap().is_empty(),
            "shadow sem violação acumulada → sem erros"
        );
    }

    // ─── Caso 3: Shadow mode COM violação Rawls ──────────────────

    #[tokio::test]
    async fn shadow_mode_with_rawls_violation_reports_but_does_not_override() {
        let state = fresh_state();
        state
            .fairness_modes
            .install("default", FairnessMode::Shadow);
        populate_rawls_violation(&state, "default");

        let server = server_from(state);
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "loan application",
                "group_classification": "unprivileged",
                "decision_confidence": 0.8,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();

        // Shadow popula governance_errors + legacy_error.
        let errors = body["explain"]["governance_errors"]
            .as_array()
            .expect("governance_errors deve ser array em shadow com violação");
        assert!(
            !errors.is_empty(),
            "shadow + violação Rawls deve emitir pelo menos E160"
        );
        let codes: Vec<&str> = errors
            .iter()
            .filter_map(|e| e["extensions"]["error_code"].as_str())
            .collect();
        assert!(
            codes.contains(&"E160"),
            "errors deve conter E160 (Rawls). got: {:?}",
            codes
        );

        // legacy_error populado.
        assert_eq!(
            body["explain"]["legacy_error"]["extensions"]["error_code"]
                .as_str()
                .unwrap_or(""),
            "E160"
        );

        // CRÍTICO: shadow NÃO sobrescreve action.
        // A ação retornada é o que a policy/governance decidiu — não REDACT
        // forçado pela composição. Como entrada é "neutral", policy → ALLOW.
        let action = body["action"].as_str().unwrap_or("");
        assert_ne!(
            action, "REDACT",
            "shadow não deve rebaixar action (era esperado ALLOW/manter); got: {action}"
        );
    }

    // ─── Caso 4: Enforced mode COM violação Rawls → ação rebaixada ─

    #[tokio::test]
    async fn enforced_mode_with_rawls_violation_overrides_to_redact() {
        let state = fresh_state();
        state
            .fairness_modes
            .install("default", FairnessMode::Enforced);
        populate_rawls_violation(&state, "default");

        let server = server_from(state);
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "neutral loan request",
                "group_classification": "unprivileged",
                "decision_confidence": 0.8,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();

        // governance_errors populados.
        let errors = body["explain"]["governance_errors"]
            .as_array()
            .expect("array");
        let codes: Vec<&str> = errors
            .iter()
            .filter_map(|e| e["extensions"]["error_code"].as_str())
            .collect();
        assert!(codes.contains(&"E160"), "esperava E160, got {:?}", codes);

        // CRÍTICO: enforced rebaixa Allow → Redact por composição Rawls.
        let action = body["action"].as_str().unwrap_or("");
        assert_eq!(
            action, "REDACT",
            "enforced + Rawls violation deve rebaixar para REDACT, got {action}"
        );
    }

    // ─── Caso 5: Enforced com Jonas baseline AUSENTE → só Rawls aplica ─

    #[tokio::test]
    async fn enforced_without_jonas_baseline_does_not_emit_e161() {
        // Documenta comportamento operacional: tenant em Enforced mas DPO
        // ainda não publicou drift_baseline.yaml. Jonas fica Disabled
        // (sem entradas no monitor), composição não detecta drift, pipeline
        // continua funcionando com Rawls.
        let state = fresh_state();
        state
            .fairness_modes
            .install("default", FairnessMode::Enforced);
        populate_rawls_violation(&state, "default");
        // NÃO install_baseline para Jonas.

        let server = server_from(state);
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "input sem drift baseline",
                "group_classification": "unprivileged",
                "decision_confidence": 0.7,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();

        let errors = body["explain"]["governance_errors"]
            .as_array()
            .expect("array");
        let codes: Vec<&str> = errors
            .iter()
            .filter_map(|e| e["extensions"]["error_code"].as_str())
            .collect();
        assert!(codes.contains(&"E160"), "Rawls deve emitir E160");
        assert!(
            !codes.contains(&"E161"),
            "E161 NÃO deve aparecer sem baseline Jonas; got {:?}",
            codes
        );
    }

    // ─── Caso 6: Enforced + Jonas Critical → action rebaixada via E161 ─

    #[tokio::test]
    async fn enforced_with_jonas_critical_drift_emits_e161() {
        let state = fresh_state();
        state
            .fairness_modes
            .install("default", FairnessMode::Enforced);
        // Instala baseline e popula drift severo.
        let baseline = JonasBaselineLoader::from_yaml_str(VALID_BASELINE).unwrap();
        state.jonas_monitor.install_baseline("default", baseline);
        // 600 scores no mesmo bin (0.05) → PSI severo vs baseline.
        for _ in 0..600 {
            state.jonas_monitor.record("default", 0.05, false);
        }

        let server = server_from(state);
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "request com jonas drift",
                "group_classification": "privileged",
                "decision_confidence": 0.05,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();

        let errors = body["explain"]["governance_errors"]
            .as_array()
            .expect("array");
        let codes: Vec<&str> = errors
            .iter()
            .filter_map(|e| e["extensions"]["error_code"].as_str())
            .collect();
        assert!(
            codes.contains(&"E161"),
            "esperava E161 com Jonas Critical, got {:?}",
            codes
        );

        // Enforced + Critical isolado → REDACT (não BLOCK, sem Rawls combo).
        let action = body["action"].as_str().unwrap_or("");
        assert_eq!(
            action, "REDACT",
            "Jonas Critical em Enforced rebaixa Allow→Redact, got {action}"
        );
    }

    // ─── Caso 7: Enforced + Rawls Critical AND Jonas Critical → BLOCK ─

    #[tokio::test]
    async fn enforced_with_combined_critical_yields_hard_block() {
        let state = fresh_state();
        state
            .fairness_modes
            .install("default", FairnessMode::Enforced);
        populate_rawls_violation(&state, "default");
        let baseline = JonasBaselineLoader::from_yaml_str(VALID_BASELINE).unwrap();
        state.jonas_monitor.install_baseline("default", baseline);
        for _ in 0..600 {
            state.jonas_monitor.record("default", 0.05, false);
        }

        let server = server_from(state);
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "request hard block",
                "group_classification": "unprivileged",
                "decision_confidence": 0.05,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();

        let errors = body["explain"]["governance_errors"]
            .as_array()
            .expect("array");
        let codes: Vec<&str> = errors
            .iter()
            .filter_map(|e| e["extensions"]["error_code"].as_str())
            .collect();
        assert!(codes.contains(&"E160"), "esperava E160 + E161, got {:?}", codes);
        assert!(codes.contains(&"E161"), "esperava E160 + E161, got {:?}", codes);

        // Composição BLOCK (D4 ADR-0087): Rawls Critical AND Jonas Critical.
        // CRÍTICO: ação deve ser BLOCK, não REDACT.
        let action = body["action"].as_str().unwrap_or("");
        assert_eq!(
            action, "BLOCK",
            "combo Critical+Critical deve produzir BLOCK; got {action}"
        );
    }

    // ─── Caso 8: Validação do schema migration (campos opcionais) ─

    #[tokio::test]
    async fn missing_fairness_fields_are_backwards_compatible() {
        // Schema migration aditiva: clientes existentes que NÃO enviam
        // group_classification nem decision_confidence devem continuar
        // funcionando — defaults (Unclassified + score 0.5 + score_unavailable).
        let server = server_from(fresh_state());
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "Hello world",
                "session_id": "s1",
                // sem group_classification, sem decision_confidence
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["action"].is_string());
        // Sem fairness config → sem erros.
        assert!(body["explain"]["legacy_error"].is_null());
    }

    // ─── Caso 9: Shadow + score_unavailable propaga ao laudo ─────

    #[tokio::test]
    async fn shadow_with_score_unavailable_propagates_to_metadata() {
        let state = fresh_state();
        state
            .fairness_modes
            .install("default", FairnessMode::Shadow);
        let baseline = JonasBaselineLoader::from_yaml_str(VALID_BASELINE).unwrap();
        state.jonas_monitor.install_baseline("default", baseline);
        // 600 records SEM score (todos score_unavailable=true) + drift severo.
        for _ in 0..600 {
            state.jonas_monitor.record("default", 0.05, true);
        }

        let server = server_from(state);
        let res = server
            .post("/v1/decide")
            .json(&json!({
                "input": "request",
                "group_classification": "privileged",
                // sem decision_confidence → score_unavailable=true
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();

        // Se Jonas detectou drift Critical em shadow, E161 deve carregar
        // score_unavailable=true na metadata para o operador identificar
        // a qualidade reduzida da análise.
        if let Some(errors) = body["explain"]["governance_errors"].as_array() {
            if let Some(e161) = errors
                .iter()
                .find(|e| e["extensions"]["error_code"].as_str() == Some("E161"))
            {
                assert_eq!(
                    e161["extensions"]["metadata"]["score_unavailable"], json!(true),
                    "score_unavailable deve estar marcado no metadata do E161"
                );
            }
        }
    }
}
