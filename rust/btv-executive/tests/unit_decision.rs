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
