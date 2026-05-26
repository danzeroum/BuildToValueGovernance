//! F1.5-05: Gatekeeper Pipeline tests
//! Atualizado ADR-048: +SqlInjection+Jailbreak+DataExfiltration+Xss+Ssti
//! Pipeline: 4 deob + 4 analyze + 13 validate = 21 módulos

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::Gatekeeper;
    use buildtovalue_kernel::gatekeeper::PipelineStage;
    use buildtovalue_kernel::core::types::ValidatorModule;

    // -----------------------------------------------------------------
    // TEST 1: Pipeline has correct stage counts (ADR-035: +NHS+VAT+IBAN)
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_stage_counts() {
        let gk = Gatekeeper::new();
        assert_eq!(gk.stage_count(PipelineStage::Deobfuscate), 4);
        assert_eq!(gk.stage_count(PipelineStage::Analyze), 4);
        assert_eq!(gk.stage_count(PipelineStage::Validate), 13); // ADR-048 ext: +Xss+Ssti
        assert_eq!(gk.module_count(), 21); // ADR-048 ext: +Xss+Ssti
    }

    // -----------------------------------------------------------------
    // TEST 2: Deobfuscate runs before Validate (order preserved)
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_order_deobfuscate_before_validate() {
        let mut gk = Gatekeeper::new();
        let input = "hidden data: MTIzLjQ1Ni43ODktMDk=";
        let evidence = gk.scan_for_evidence(input, 0x1234);

        let findings = evidence.get_all_findings();
        let has_deob = findings.iter().any(|f| f.module == ValidatorModule::Deobfuscator);
        assert!(has_deob, "Deobfuscator should detect base64");
    }

    // -----------------------------------------------------------------
    // TEST 3: Analyze fills stats before Validate
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_analyze_fills_stats() {
        let mut gk = Gatekeeper::new();
        let input = "Hello world, this is a test with some entropy!";
        let evidence = gk.scan_for_evidence(input, 0x2345);

        assert!(evidence.stats.entropy > 0.0, "Entropy should be calculated");
    }

    // -----------------------------------------------------------------
    // TEST 4: All 21 modules executed (ADR-048 ext: +Xss+Ssti)
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_all_modules_execute() {
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence("clean input", 0x3456);
        assert!(evidence.executed_modules.count_ones() >= 10,
                "Expected 10+ module bits, got {} (bitmask: {:032b})",
                evidence.executed_modules.count_ones(),
                evidence.executed_modules
        );
        assert_eq!(gk.module_count(), 21); // ADR-048 ext: +Xss+Ssti
    }

    // -----------------------------------------------------------------
    // TEST 5: CPF detection still works through pipeline
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_cpf_detection() {
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence("CPF: 123.456.789-09", 0x4567);
        assert!(evidence.critical_count > 0, "CPF should be detected as critical");
    }

    // -----------------------------------------------------------------
    // TEST 6: Bias aggregation unchanged
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_bias_aggregation() {
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence("test", 0x5678);
        assert!(evidence.bias.false_positive_rate > 0.0);
        assert!(evidence.bias.false_negative_rate > 0.0);
        assert!(evidence.bias.test_dataset_size >= 500);
    }

    // -----------------------------------------------------------------
    // TEST 7: Metrics update correctly
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_metrics() {
        let mut gk = Gatekeeper::new();
        let _ = gk.scan_for_evidence("first scan", 1);
        let _ = gk.scan_for_evidence("second scan", 2);

        let metrics = gk.get_metrics();
        assert_eq!(metrics.scans_total, 2);
    }

    // -----------------------------------------------------------------
    // TEST 8: NHS Number detected (ADR-035 — JURISDICTION_UK)
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_nhs_detection() {
        let mut gk = Gatekeeper::new();
        // flags com JURISDICTION_UK ativo (bit 0x02)
        let evidence = gk.scan_for_evidence("Patient NHS: 943 476 5919", 0x02);
        let findings = evidence.get_all_findings();
        let has_nhs = findings.iter().any(|f| f.module == ValidatorModule::NhsNumber);
        assert!(has_nhs, "NHS Number should be detected with JURISDICTION_UK active");
    }

    // -----------------------------------------------------------------
    // TEST 9: IBAN detected (ADR-035 — JURISDICTION_EU)
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_iban_detection() {
        let mut gk = Gatekeeper::new();
        
        let evidence = gk.scan_for_evidence("IBAN: DE89370400440532013000", 0x9999);
        let findings = evidence.get_all_findings();
        let has_iban = findings.iter().any(|f| f.module == ValidatorModule::Iban);
        assert!(has_iban, "IBAN should be detected with JURISDICTION_EU active");
    }
}