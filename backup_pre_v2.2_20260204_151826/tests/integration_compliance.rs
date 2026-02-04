
#[test]
fn test_end_to_end_compliance_flow() {
    // 1. Rust calculates penalty
    let penalty = PenaltyCalculatorV2::calculate(
        ThreatType::PIILeakage,
        RegulatoryFramework::LGPD,
    ).unwrap();
    
    assert_eq!(penalty.per_incident_usd, 50_000_00);
    
    // 2. Threat ingestor persists to WAL
    let mut ingestor = ThreatIngestorV2::new("test.wal").unwrap();
    let event = ThreatEvent {
        id: "test-001".to_string(),
        threat_type: "pii_leakage".to_string(),
        severity: 9,
        source: "buildtovalue".to_string(),
        indicators: vec!["CPF".to_string()],
        timestamp: chrono::Utc::now().timestamp(),
        hash: String::new(),
    };
    ingestor.ingest(event).unwrap();
    
    // 3. Query by type
    let results = ingestor.query_by_type("pii_leakage");
    assert_eq!(results.len(), 1);
    
    // 4. Calculate ROI for batch
    let threats = vec![
        (ThreatType::PIILeakage, RegulatoryFramework::LGPD),
        (ThreatType::ShadowAI, RegulatoryFramework::EUAIAct),
    ];
    let total = PenaltyCalculatorV2::calculate_roi_batch(&threats);
    assert!(total > 0);
}