//! Unit tests for `DecisionMaker` — Critérios 2, 3, 4, 6
//!
//! Tests isolados: não precisam de btv-sigma nem de LogClient.
//! Cobrem: input limpo → Allow, CPF → Deny, input vazio → GatekeeperFailed,
//! e a ausência de variante parcial em `DecisionError`.

#[cfg(test)]
mod decision_maker_unit {
    use btv_executive::{DecisionMaker, Decision};
    use btv_executive::error::DecisionError;

    // ── Critério 6: DecisionError sem resultado parcial ───────────────────────────

    /// Compile-time test: exhaustive match on DecisionError MUST NOT include
    /// any variant that carries a Verdict, InclusionReceipt, or DeliveryToken.
    /// If a future variant adds a partial result, this match will no longer
    /// compile unless the new variant is also handled — making the oversight visible.
    fn _assert_no_partial_result(e: DecisionError) -> &'static str {
        match e {
            DecisionError::GatekeeperFailed(_)      => "gatekeeper",
            DecisionError::ComplianceUnavailable(_) => "compliance",
            DecisionError::LogUnavailable(_)        => "log",
            DecisionError::IntegrityFailure         => "integrity",
            DecisionError::InputViolation(_)        => "input",
        }
    }

    #[test]
    fn decision_error_exhaustive_no_partial_result() {
        // The _assert_no_partial_result function compiling IS the test.
        // If DecisionError gains a partial-result variant, this test fails to compile.
        let _ = _assert_no_partial_result;
    }

    // ── Critério 2: scan limpo → Allow ─────────────────────────────────────────────

    #[test]
    fn clean_input_decides_allow() {
        use btv_executive::__testhelpers::make_scan_result;
        let scan = make_scan_result(vec![], 0.1);
        let dm = DecisionMaker::default_thresholds();
        assert_eq!(dm.decide(&scan), Decision::Allow);
    }

    // ── Critério 3: finding crítico → Deny ───────────────────────────────────────

    #[test]
    fn critical_finding_decides_deny() {
        use btv_executive::__testhelpers::{make_scan_result, make_finding};
        let scan = make_scan_result(
            vec![make_finding("PII-001", "CPF", 230, 200)],
            0.9,
        );
        let dm = DecisionMaker::default_thresholds();
        assert_eq!(dm.decide(&scan), Decision::Deny);
    }

    #[test]
    fn high_composite_risk_decides_deny() {
        use btv_executive::__testhelpers::make_scan_result;
        let scan = make_scan_result(vec![], 0.85); // above 0.80 threshold
        let dm = DecisionMaker::default_thresholds();
        assert_eq!(dm.decide(&scan), Decision::Deny);
    }

    #[test]
    fn low_composite_risk_decides_allow() {
        use btv_executive::__testhelpers::make_scan_result;
        let scan = make_scan_result(vec![], 0.3);
        let dm = DecisionMaker::default_thresholds();
        assert_eq!(dm.decide(&scan), Decision::Allow);
    }

    // ── ADR-061: Decision::Block ──────────────────────────────────────────────────────

    #[test]
    fn active_threat_risk_decides_block() {
        use btv_executive::__testhelpers::make_scan_result;
        let scan = make_scan_result(vec![], 0.97); // above threat_threshold=0.95
        let dm = DecisionMaker::default_thresholds();
        assert_eq!(dm.decide(&scan), Decision::Block);
    }

    #[test]
    fn block_requires_security_alert() {
        assert!(Decision::Block.requires_security_alert());
        assert!(!Decision::Allow.requires_security_alert());
        assert!(!Decision::Deny.requires_security_alert());
    }

    #[test]
    fn all_decisions_are_contestable() {
        assert!(Decision::Allow.is_contestable());
        assert!(Decision::Deny.is_contestable());
        assert!(Decision::Block.is_contestable());
    }

    #[test]
    fn deny_threshold_still_decides_deny_not_block() {
        use btv_executive::__testhelpers::make_scan_result;
        // 0.85 is above deny_threshold=0.80 but below threat_threshold=0.95
        let scan = make_scan_result(vec![], 0.85);
        let dm = DecisionMaker::default_thresholds();
        assert_eq!(dm.decide(&scan), Decision::Deny);
    }

    #[test]
    fn block_explanation_contains_block() {
        use btv_executive::__testhelpers::make_scan_result;
        let scan = make_scan_result(vec![], 0.97);
        let dm = DecisionMaker::default_thresholds();
        let explanation = dm.explain(&scan, &Decision::Block);
        assert!(explanation.contains("BLOCK"), "got: {explanation}");
    }

    #[test]
    fn decision_repr_u8_values_are_stable() {
        // CRITICAL: repr(u8) discriminant values are fixed — historical Ledger data depends on them.
        // Allow=0 and Deny=1 existed before ADR-061; Block=2 is new.
        // These values must NEVER be reordered.
        assert_eq!(Decision::Allow as u8, 0);
        assert_eq!(Decision::Deny  as u8, 1);
        assert_eq!(Decision::Block as u8, 2);
    }

    // ── ADR-060: BiasDeclaration ──────────────────────────────────────────────────────

    #[test]
    fn bootstrap_bias_declaration_is_detectable() {
        use btv_types::BiasDeclaration;
        let b = BiasDeclaration::bootstrap_unvalidated();
        assert!(b.is_bootstrap(), "bootstrap value must be detectable via is_bootstrap()");
    }

    #[test]
    fn non_bootstrap_bias_declaration_not_detected() {
        use btv_types::BiasDeclaration;
        let b = BiasDeclaration {
            false_positive_rate: 0.05,
            false_negative_rate: 0.03,
            validated_groups: vec!["pt-BR".to_string()],
            known_disparities: vec![],
            measurement_tool_version: "fairlearn-0.10.0".to_string(),
        };
        assert!(!b.is_bootstrap());
    }

    // ── ADR-062: AppealRecord ─────────────────────────────────────────────────────────

    #[test]
    fn appeal_record_sla_within_deadline() {
        use btv_types::AppealRecord;
        use btv_types::BiasDeclaration;
        let record = AppealRecord {
            evidence_hash: [0u8; 32],
            explanation_text: "test".to_string(),
            bias_declaration: BiasDeclaration::bootstrap_unvalidated(),
            deadlock_reason: None,
            appeal_token: "abc".to_string(),
            appeal_sla_deadline: 1000,
            created_at: 0,
        };
        assert!(record.is_within_sla(999));
        assert!(!record.is_within_sla(1000));
        assert!(!record.is_within_sla(1001));
    }

    // ── Explanation strings ───────────────────────────────────────────────────────────

    #[test]
    fn allow_explanation_contains_allow() {
        use btv_executive::__testhelpers::make_scan_result;
        let scan = make_scan_result(vec![], 0.1);
        let dm = DecisionMaker::default_thresholds();
        let decision = Decision::Allow;
        let explanation = dm.explain(&scan, &decision);
        assert!(explanation.contains("ALLOW"), "got: {explanation}");
    }

    #[test]
    fn deny_explanation_contains_deny() {
        use btv_executive::__testhelpers::{make_scan_result, make_finding};
        let scan = make_scan_result(
            vec![make_finding("PAT-001", "Prompt Injection", 240, 220)],
            0.95,
        );
        let dm = DecisionMaker::default_thresholds();
        let decision = Decision::Deny;
        let explanation = dm.explain(&scan, &decision);
        assert!(explanation.contains("DENY"), "got: {explanation}");
    }
}
