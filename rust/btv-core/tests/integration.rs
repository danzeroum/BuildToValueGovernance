/// Integration tests for btv-core happy paths.
///
/// Run with: BTV_HMAC_KEY=test-key cargo test -p btv-core
use btv_core::{
    ComplianceAuthority, ComplianceError, ComplianceRegistry,
    Decision, EvidenceToken, OperatorToken, EscalatedVerdict, Verdict,
};

// ── Test registry ─────────────────────────────────────────────────────────────

struct TestRegistry;

impl ComplianceRegistry for TestRegistry {
    fn validate(&self, jurisdiction: &str, policy_version: &str) -> Result<u32, ComplianceError> {
        match (jurisdiction, policy_version) {
            ("BR", "LGPD-v1") => Ok(720),  // 30 days
            ("EU", "GDPR-v4") => Ok(2160), // 90 days
            (j, _) => Err(ComplianceError::UnknownJurisdiction(j.to_string())),
        }
    }
}

fn make_authority() -> ComplianceAuthority {
    ComplianceAuthority::new(Box::new(TestRegistry))
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn verdict_new_produces_valid_record() {
    std::env::set_var("BTV_HMAC_KEY", "integration-test-key");

    let authority = make_authority();
    let evidence = EvidenceToken::new(b"user submitted: hello world");
    let compliance = authority.issue("BR", "LGPD-v1").expect("valid jurisdiction");

    let verdict = Verdict::new(evidence, compliance, Decision::Allow, "no violations found".to_string());

    assert!(verdict.verify_integrity(), "HMAC seal must be valid");
    assert_eq!(verdict.decision(), Decision::Allow);
    assert_eq!(verdict.jurisdiction(), "BR");
    assert_eq!(verdict.policy_version(), "LGPD-v1");

    let record = verdict.to_record();
    assert_eq!(record.decision, Decision::Allow);
    assert_eq!(record.legislative_version, 0); // Phase 6 placeholder
    assert_ne!(record.hmac_tag, [0u8; 32]);
}

#[test]
fn verdict_deny_round_trip() {
    std::env::set_var("BTV_HMAC_KEY", "integration-test-key");

    let authority = make_authority();
    let evidence = EvidenceToken::new(b"suspicious: inject; DROP TABLE");
    let compliance = authority.issue("EU", "GDPR-v4").expect("valid jurisdiction");

    let verdict = Verdict::new(evidence, compliance, Decision::Deny, "SQL injection detected".to_string());

    assert!(verdict.verify_integrity());
    assert_eq!(verdict.decision(), Decision::Deny);

    let record = verdict.to_record();
    assert_eq!(record.decision, Decision::Deny);
}

#[test]
fn compliance_authority_rejects_unknown_jurisdiction() {
    let authority = make_authority();
    let result = authority.issue("XX", "Unknown-v0");
    assert!(matches!(result, Err(ComplianceError::UnknownJurisdiction(_))));
}

#[test]
fn escalated_verdict_consumes_operator_token() {
    let token = OperatorToken::new("operator@example.com".to_string());
    let verdict = EscalatedVerdict::new(token, "Input blocked — operator review required".to_string());

    assert_eq!(verdict.operator_id(), "operator@example.com");
    assert_eq!(verdict.reason(), "Input blocked — operator review required");
}

#[test]
fn record_evidence_hash_is_deterministic() {
    std::env::set_var("BTV_HMAC_KEY", "integration-test-key");

    let context = b"deterministic context";
    let authority = make_authority();

    let e1 = EvidenceToken::new(context);
    let c1 = authority.issue("BR", "LGPD-v1").unwrap();
    let v1 = Verdict::new(e1, c1, Decision::Allow, "ok".to_string());

    let e2 = EvidenceToken::new(context);
    let c2 = authority.issue("BR", "LGPD-v1").unwrap();
    let v2 = Verdict::new(e2, c2, Decision::Allow, "ok".to_string());

    // Same context → same evidence hash
    assert_eq!(v1.to_record().evidence_hash, v2.to_record().evidence_hash);
}
