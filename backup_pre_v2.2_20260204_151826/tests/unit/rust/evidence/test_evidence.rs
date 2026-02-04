
use buildtovalue::kernel::evidence::{TechnicalEvidence, Finding};
use buildtovalue::kernel::validators::{ValidatorModule, TechnicalSeverity};

#[test]
fn test_evidence_initialization() {
    let evidence = TechnicalEvidence::new(0x12345678);
    
    assert_eq!(evidence.protocol_version, 2);
    assert_eq!(evidence.audit_trail_id, 0x12345678);
    assert_eq!(evidence.finding_count, 0);
    assert_eq!(evidence.critical_count, 0);
    assert_eq!(evidence.composite_risk, 0);
}

#[test]
fn test_evidence_ring_buffer() {
    let mut evidence = TechnicalEvidence::new(0x1234);
    
    // Adiciona 15 findings (excede capacidade de 10)
    for i in 0..15 {
        let finding = Finding::new(
            ValidatorModule::Entropy,
            TechnicalSeverity::Low,
            &format!("FINDING_{}", i),
            "Test finding",
            &format!("Description {}", i),
        );
        evidence.add_finding(finding);
    }
    
    // Valida: apenas últimos 10 mantidos
    assert_eq!(evidence.finding_count, 10);
    
    // Valida: findings 5-14 estão presentes (0-4 foram sobrescritos)
    let findings = evidence.get_all_findings();
    let titles: Vec<String> = findings.iter()
        .map(|f| std::str::from_utf8(&f.title).unwrap().trim_end_matches('\0').to_string())
        .collect();
    
    assert!(titles.contains(&"FINDING_14".to_string()));
    assert!(!titles.contains(&"FINDING_0".to_string()));
}

#[test]
fn test_evidence_critical_preservation() {
    let mut evidence = TechnicalEvidence::new(0x1234);
    
    // Adiciona 5 findings normais
    for i in 0..5 {
        evidence.add_finding(Finding::new(
            ValidatorModule::ZScore,
            TechnicalSeverity::Medium,
            "MEDIUM",
            "Medium priority",
            "...",
        ));
    }
    
    // Adiciona 2 critical
    evidence.add_finding(Finding::new(
        ValidatorModule::CPF,
        TechnicalSeverity::Critical,
        "CPF_CRITICAL",
        "Critical CPF",
        "...",
    ));
    
    evidence.add_finding(Finding::new(
        ValidatorModule::CreditCard,
        TechnicalSeverity::Critical,
        "CARD_CRITICAL",
        "Critical Card",
        "...",
    ));
    
    // Adiciona mais 10 normais (sobrescreve anteriores)
    for i in 0..10 {
        evidence.add_finding(Finding::new(
            ValidatorModule::Entropy,
            TechnicalSeverity::Low,
            "LOW",
            "Low priority",
            "...",
        ));
    }
    
    // Valida: Critical findings ainda estão lá
    assert_eq!(evidence.critical_count, 2);
    
    let critical_titles: Vec<String> = evidence.critical
        .iter()
        .take(evidence.critical_count as usize)
        .map(|f| std::str::from_utf8(&f.title).unwrap().trim_end_matches('\0').to_string())
        .collect();
    
    assert!(critical_titles.contains(&"CPF_CRITICAL".to_string()));
    assert!(critical_titles.contains(&"CARD_CRITICAL".to_string()));
}

#[test]
fn test_evidence_hash_determinism() {
    let mut evidence1 = TechnicalEvidence::new(0x1234);
    let mut evidence2 = TechnicalEvidence::new(0x1234);
    
    // Adiciona mesmos findings
    for i in 0..3 {
        let finding = Finding::new(
            ValidatorModule::CPF,
            TechnicalSeverity::PolicyViolation,
            "CPF_TEST",
            "Test CPF",
            "Description",
        );
        evidence1.add_finding(finding.clone());
        evidence2.add_finding(finding);
    }
    
    evidence1.finalize().unwrap();
    evidence2.finalize().unwrap();
    
    // Hashes devem ser idênticos
    assert_eq!(evidence1.evidence_hash, evidence2.evidence_hash);
    assert_eq!(evidence1.checksum, evidence2.checksum);
}

#[test]
fn test_evidence_hash_collision_resistance() {
    let mut evidence1 = TechnicalEvidence::new(0x1234);
    let mut evidence2 = TechnicalEvidence::new(0x1234);
    
    // Adiciona findings DIFERENTES
    evidence1.add_finding(Finding::new(
        ValidatorModule::CPF,
        TechnicalSeverity::PolicyViolation,
        "CPF_A",
        "CPF A",
        "Description A",
    ));
    
    evidence2.add_finding(Finding::new(
        ValidatorModule::CNPJ,
        TechnicalSeverity::Low,
        "CNPJ_B",
        "CNPJ B",
        "Description B",
    ));
    
    evidence1.finalize().unwrap();
    evidence2.finalize().unwrap();
    
    // Hashes devem ser DIFERENTES
    assert_ne!(evidence1.evidence_hash, evidence2.evidence_hash);
}

#[test]
fn test_evidence_tampering_detection() {
    let mut evidence = TechnicalEvidence::new(0x1234);
    
    evidence.add_finding(Finding::new(
        ValidatorModule::CPF,
        TechnicalSeverity::PolicyViolation,
        "CPF_001",
        "CPF detected",
        "...",
    ));
    
    evidence.finalize().unwrap();
    
    // Valida integridade original
    assert!(evidence.validate());
    
    // Simula tampering (modifica composite_risk)
    let original_risk = evidence.composite_risk;
    evidence.composite_risk = 0; // Atenua artificialmente
    
    // Valida: tampering detectado
    assert!(!evidence.validate());
    
    // Restaura
    evidence.composite_risk = original_risk;
    assert!(evidence.validate());
}

#[test]
fn test_evidence_composite_risk_calculation() {
    let mut evidence = TechnicalEvidence::new(0x1234);
    
    // Caso 1: Sem findings → risk = 0
    evidence.finalize().unwrap();
    assert_eq!(evidence.composite_risk, 0);
    
    // Caso 2: 1 CPF (PolicyViolation=192, confidence=255)
    let mut evidence = TechnicalEvidence::new(0x1235);
    evidence.add_finding(Finding {
        module: ValidatorModule::CPF,
        severity: TechnicalSeverity::PolicyViolation,
        rule_id: 1,
        title: *b"CPF_TEST\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        description: [0u8; 128],
        confidence: 255,
        position_start: 0,
        position_end: 10,
        _padding: [0u8; 6],
    });
    evidence.finalize().unwrap();
    
    // risk = (192 * 255) / 255 = 192
    assert_eq!(evidence.composite_risk, 192);
}

#[test]
fn test_evidence_fixed_size() {
    use std::mem::size_of;
    
    // Valida que TechnicalEvidence tem tamanho fixo (9.4KB)
    assert_eq!(size_of::<TechnicalEvidence>(), 9596);
}

#[test]
fn test_evidence_serialization() {
    let mut evidence = TechnicalEvidence::new(0x1234);
    
    evidence.add_finding(Finding::new(
        ValidatorModule::CPF,
        TechnicalSeverity::PolicyViolation,
        "CPF_TEST",
        "Test",
        "...",
    ));
    
    evidence.finalize().unwrap();
    
    // Serializa para bytes
    let bytes = evidence.to_bytes();
    assert_eq!(bytes.len(), 9596);
    
    // Deserializa
    let evidence2 = TechnicalEvidence::from_bytes(&bytes).unwrap();
    
    // Valida integridade
    assert_eq!(evidence.evidence_hash, evidence2.evidence_hash);
    assert_eq!(evidence.audit_trail_id, evidence2.audit_trail_id);
}

#[test]
fn test_evidence_bias_declaration() {
    let evidence = TechnicalEvidence::new(0x1234);
    
    let bias = evidence.bias;
    
    // Verifica BiasDeclaration está populado
    assert!(bias.false_positive_rate > 0.0);
    assert!(bias.false_positive_rate <= 1.0);
    assert!(bias.calibration_date > 0);
    
    // Verifica limitações estão documentadas
    let limitations = std::str::from_utf8(&bias.limitations)
        .unwrap()
        .trim_end_matches('\0');
    assert!(!limitations.is_empty());
    assert!(limitations.contains("CPF") || limitations.contains("calibr"));
}