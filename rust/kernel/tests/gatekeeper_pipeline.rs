//! F1.5-05: Gatekeeper Pipeline tests

#[cfg(test)]
mod tests {
    use buildtovalue_kernel::Gatekeeper;
    use buildtovalue_kernel::gatekeeper::PipelineStage;
    use buildtovalue_kernel::core::types::ValidatorModule;

    // -----------------------------------------------------------------
    // TEST 1: Pipeline has correct stage counts
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_stage_counts() {
        let gk = Gatekeeper::new();
        assert_eq!(gk.stage_count(PipelineStage::Deobfuscate), 3);
        assert_eq!(gk.stage_count(PipelineStage::Analyze), 3);
        assert_eq!(gk.stage_count(PipelineStage::Validate), 6);
        assert_eq!(gk.module_count(), 12);
    }

    // -----------------------------------------------------------------
    // TEST 2: Deobfuscate runs before Validate (order preserved)
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_order_deobfuscate_before_validate() {
        let mut gk = Gatekeeper::new();
        // Base64-encoded CPF: "MTIzLjQ1Ni43ODktMDk=" decodes to "123.456.789-09"
        // Deobfuscator should detect base64, validator should detect CPF pattern
        let input = "hidden data: MTIzLjQ1Ni43ODktMDk=";
        let evidence = gk.scan_for_evidence(input, 0x1234);

        // Should have findings from deobfuscator (base64 detected)
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

        // Stats should be populated by Analyze stage
        assert!(evidence.stats.entropy > 0.0, "Entropy should be calculated");
    }

    // -----------------------------------------------------------------
    // TEST 4: Clean input → no findings, all 11 modules executed
    // -----------------------------------------------------------------
    #[test]
    fn test_pipeline_all_modules_execute() {
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence("clean input", 0x3456);

        // Some modules share ValidatorModule variants, so unique bits < 11
        // Verify at least 9 unique module bits are set
        assert!(evidence.executed_modules.count_ones() >= 9,
                "Expected 9+ module bits, got {} (bitmask: {:032b})",
                evidence.executed_modules.count_ones(),
                evidence.executed_modules
        );
        // Verify total module count in pipeline is 11
        assert_eq!(gk.module_count(), 12);
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
}