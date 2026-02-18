
use quickcheck::{quickcheck, TestResult};
use buildtovalue::kernel::evidence::TechnicalEvidence;

quickcheck! {
    /// Property: Hashes idênticos para inputs idênticos (determinismo)
    fn prop_hash_deterministic(audit_trail_id: u64, finding_count: u8) -> TestResult {
        if finding_count > 10 {
            return TestResult::discard();
        }
        
        let mut evidence1 = TechnicalEvidence::new(audit_trail_id);
        let mut evidence2 = TechnicalEvidence::new(audit_trail_id);
        
        // Adiciona mesmos findings
        for i in 0..finding_count {
            let finding = create_test_finding(i);
            evidence1.add_finding(finding.clone());
            evidence2.add_finding(finding);
        }
        
        evidence1.finalize().unwrap();
        evidence2.finalize().unwrap();
        
        TestResult::from_bool(
            evidence1.evidence_hash == evidence2.evidence_hash &&
            evidence1.checksum == evidence2.checksum
        )
    }
    
    /// Property: Hashes diferentes para inputs diferentes
    fn prop_hash_collision_resistance(
        audit_trail_id1: u64,
        audit_trail_id2: u64
    ) -> TestResult {
        if audit_trail_id1 == audit_trail_id2 {
            return TestResult::discard();
        }
        
        let mut evidence1 = TechnicalEvidence::new(audit_trail_id1);
        let mut evidence2 = TechnicalEvidence::new(audit_trail_id2);
        
        evidence1.finalize().unwrap();
        evidence2.finalize().unwrap();
        
        // Hashes devem ser diferentes (alta probabilidade)
        TestResult::from_bool(evidence1.evidence_hash != evidence2.evidence_hash)
    }
    
    /// Property: Validação detecta tampering
    fn prop_validation_detects_tampering(
        audit_trail_id: u64,
        tampered_risk: u8
    ) -> TestResult {
        let mut evidence = TechnicalEvidence::new(audit_trail_id);
        
        evidence.add_finding(create_test_finding(0));
        evidence.finalize().unwrap();
        
        // Valida antes de tampering
        assert!(evidence.validate());
        
        // Tampering
        let original_risk = evidence.composite_risk;
        evidence.composite_risk = tampered_risk;
        
        if tampered_risk == original_risk {
            return TestResult::discard(); // Não é tampering
        }
        
        // Validação deve falhar
        TestResult::from_bool(!evidence.validate())
    }
    
    /// Property: Checksum único para cada estado
    fn prop_checksum_uniqueness(finding_count1: u8, finding_count2: u8) -> TestResult {
        if finding_count1 > 10 || finding_count2 > 10 || finding_count1 == finding_count2 {
            return TestResult::discard();
        }
        
        let mut evidence1 = TechnicalEvidence::new(0x1234);
        let mut evidence2 = TechnicalEvidence::new(0x1234);
        
        for i in 0..finding_count1 {
            evidence1.add_finding(create_test_finding(i));
        }
        
        for i in 0..finding_count2 {
            evidence2.add_finding(create_test_finding(i));
        }
        
        evidence1.finalize().unwrap();
        evidence2.finalize().unwrap();
        
        // Checksums devem ser diferentes
        TestResult::from_bool(evidence1.checksum != evidence2.checksum)
    }
}

// Helper
fn create_test_finding(index: u8) -> Finding {
    Finding::new(
        ValidatorModule::CPF,
        TechnicalSeverity::PolicyViolation,
        &format!("TEST_{}", index),
        "Test finding",
        "...",
    )
}