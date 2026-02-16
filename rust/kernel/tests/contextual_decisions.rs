//! F1.7-04: Contextual tests — same input, different outcomes based on context.

#[cfg(test)]
mod tests {
    use buildtovalue_kernel::gatekeeper::Gatekeeper;
    use buildtovalue_kernel::policy::{PolicyEngine, PolicyAction};
    use buildtovalue_kernel::network::{IpClassifier, IpCategory, IpRisk};
    use buildtovalue_kernel::session_guard::{SessionDrift, SessionVector, DriftLevel};
    use buildtovalue_kernel::interceptor::{InterceptorChain, InterceptAction, MaxLengthHook};

    const CPF_INPUT: &str = "My CPF is 123.456.789-09";

    fn policy_yaml() -> &'static str {
        r#"
version: "1.7"
metadata:
  name: "Contextual"
  description: "Test"
  created_at: "2026-02-15"
  updated_at: "2026-02-15"
  author: "Test"
hard_blocks:
  - "DROP TABLE"
policies:
  - id: "block-cpf"
    name: "Block CPF"
    description: "Block CPF high confidence"
    enabled: true
    priority: 100
    conditions:
      validators: ["cpf"]
      min_severity: 0.5
      min_confidence: 0.9
    action: BLOCK
  - id: "log-low"
    name: "Log low"
    description: "Log low confidence"
    enabled: true
    priority: 10
    conditions:
      validators: []
      min_severity: 0.0
      min_confidence: 0.0
    action: LOG
"#
    }

    // -----------------------------------------------------------------
    // TEST 1: Same CPF input — residential IP vs Tor IP
    // -----------------------------------------------------------------
    #[test]
    fn test_same_input_different_ip_context() {
        let classifier = IpClassifier::new();

        let residential = classifier.classify("189.50.100.1");
        let tor = classifier.classify("185.220.100.50");

        // Same input, but IP context changes risk assessment
        assert_eq!(residential.risk, IpRisk::Low);
        assert_eq!(tor.risk, IpRisk::Critical);

        // Decision: residential → policy decides; tor → elevated risk
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence(CPF_INPUT, 0x1234);
        assert!(evidence.critical_count > 0); // CPF detected either way

        // But tor IP would escalate the action in governance layer
        assert_eq!(tor.category, IpCategory::Tor);
        assert_eq!(residential.category, IpCategory::Residential);
    }

    // -----------------------------------------------------------------
    // TEST 2: Same CPF input — normal session vs drifted session
    // -----------------------------------------------------------------
    #[test]
    fn test_same_input_different_session_drift() {
        let sd = SessionDrift::new();

        let baseline = SessionVector {
            avg_input_len: 30.0, avg_entropy: 2.5, finding_rate: 0.0,
            critical_rate: 0.0, pii_rate: 0.0, request_frequency: 1.0,
        };

        // Normal continuation
        let normal_current = SessionVector {
            avg_input_len: 35.0, avg_entropy: 2.8, finding_rate: 0.05,
            critical_rate: 0.0, pii_rate: 0.02, request_frequency: 1.2,
        };

        // Suspicious drift (suddenly sending PII at high rate)
        let suspicious_current = SessionVector {
            avg_input_len: 0.0, avg_entropy: 0.0, finding_rate: 1.0,
            critical_rate: 1.0, pii_rate: 1.0, request_frequency: 0.0,
        };

        let normal_result = sd.compare(&baseline, &normal_current);
        let suspicious_result = sd.compare(&baseline, &suspicious_current);

        assert_eq!(normal_result.level, DriftLevel::None);
        assert!(!normal_result.identity_challenge);

        assert!(matches!(
            suspicious_result.level,
            DriftLevel::High | DriftLevel::Critical
        ));
        assert!(suspicious_result.identity_challenge);
    }

    // -----------------------------------------------------------------
    // TEST 3: Same CPF input — passes interceptor vs blocked by length
    // -----------------------------------------------------------------
    #[test]
    fn test_same_input_different_interceptor_config() {
        // Permissive config
        let mut permissive = InterceptorChain::new();
        permissive.add_request_hook(Box::new(MaxLengthHook::new(1000)));
        let (action, _) = permissive.run_request(CPF_INPUT);
        assert_eq!(action, InterceptAction::Continue);

        // Strict config (max 10 chars)
        let mut strict = InterceptorChain::new();
        strict.add_request_hook(Box::new(MaxLengthHook::new(10)));
        let (action, _) = strict.run_request(CPF_INPUT);
        assert!(matches!(action, InterceptAction::Block(_)));
    }

    // -----------------------------------------------------------------
    // TEST 4: Same input — policy BLOCK vs no-policy ALLOW
    // -----------------------------------------------------------------
    #[test]
    fn test_same_findings_different_policy() {
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence(CPF_INPUT, 0x1234);
        let findings: Vec<_> = evidence.get_all_findings();

        // With strict policy → should escalate beyond ALLOW
        let mut strict = PolicyEngine::from_yaml_str(policy_yaml()).unwrap();
        let eval_strict = strict.evaluate_full(CPF_INPUT, &findings);

        // With empty policy → ALLOW
        let empty_yaml = r#"
version: "1.0"
metadata:
  name: "Empty"
  description: "No policies"
  created_at: "2026-01-01"
  updated_at: "2026-01-01"
  author: "Test"
policies: []
"#;
        let mut permissive = PolicyEngine::from_yaml_str(empty_yaml).unwrap();
        let eval_permissive = permissive.evaluate_full(CPF_INPUT, &findings);

        // Strict should be MORE severe than permissive
        assert!(
            eval_strict.action.severity_level() > eval_permissive.action.severity_level(),
            "Strict={:?} should be more severe than permissive={:?}",
            eval_strict.action, eval_permissive.action
        );
        assert_eq!(eval_permissive.action, PolicyAction::Allow);
    }
    // -----------------------------------------------------------------
    // TEST 5: Hard block input — always blocked regardless of context
    // -----------------------------------------------------------------
    #[test]
    fn test_hard_block_ignores_context() {
        let mut engine = PolicyEngine::from_yaml_str(policy_yaml()).unwrap();
        let malicious = "SELECT * FROM users; DROP TABLE users";
        let eval = engine.evaluate_full(malicious, &[]);
        assert!(eval.hard_blocked);
        assert_eq!(eval.action, PolicyAction::Block);
    }

    // -----------------------------------------------------------------
    // TEST 6: Clean input — always allowed regardless of strict policy
    // -----------------------------------------------------------------
    #[test]
    fn test_clean_input_allowed_in_all_contexts() {
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence("Hello, how are you?", 0x5678);
        let findings: Vec<_> = evidence.get_all_findings();

        let mut engine = PolicyEngine::from_yaml_str(policy_yaml()).unwrap();
        let eval = engine.evaluate_full("Hello, how are you?", &findings);

        // Clean input with no PII findings → LOG at most (wildcard rule)
        assert_ne!(eval.action, PolicyAction::Block);
    }

    // -----------------------------------------------------------------
    // TEST 7: VPN + drift + CPF = maximum context risk
    // -----------------------------------------------------------------
    #[test]
    fn test_combined_context_escalation() {
        let classifier = IpClassifier::new();
        let ip = classifier.classify("146.70.50.1"); // VPN

        let sd = SessionDrift::new();
        let baseline = SessionVector {
            avg_input_len: 20.0, avg_entropy: 2.0, finding_rate: 0.0,
            critical_rate: 0.0, pii_rate: 0.0, request_frequency: 0.5,
        };
        let current = SessionVector {
            avg_input_len: 0.0, avg_entropy: 0.0, finding_rate: 1.0,
            critical_rate: 1.0, pii_rate: 1.0, request_frequency: 0.0,
        };
        let drift = sd.compare(&baseline, &current);

        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence(CPF_INPUT, 0x9999);

        // All 3 signals are high risk
        assert_eq!(ip.risk, IpRisk::High);
        assert!(drift.identity_challenge);
        assert!(evidence.critical_count > 0);

        // Combined: this would be maximum escalation in governance
        let risk_signals = [
            ip.risk == IpRisk::High || ip.risk == IpRisk::Critical,
            drift.identity_challenge,
            evidence.critical_count > 0,
        ];
        let risk_count = risk_signals.iter().filter(|&&r| r).count();
        assert_eq!(risk_count, 3, "All 3 risk signals should fire");
    }
}