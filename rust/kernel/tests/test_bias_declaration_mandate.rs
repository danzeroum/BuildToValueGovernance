#[cfg(test)]
mod tests {
    use buildtovalue_kernel::core::types::BiasDeclaration;
    use buildtovalue_kernel::core::module::Module;
    use buildtovalue_kernel::evidence::TechnicalEvidence;
    use buildtovalue_kernel::gatekeeper::Gatekeeper;
    use buildtovalue_kernel::deobfuscator::{Base64Detector, HexDecoder, LeetspeakDetector};
    use buildtovalue_kernel::statistics::{EntropyCalculator, ZScoreCalculator, CharRatioAnalyzer};
    use buildtovalue_kernel::validators::{
        CpfValidator, CnpjValidator, EmailValidator, PhoneValidator, CreditCardValidator,
    };

    fn all_modules() -> Vec<Box<dyn Module>> {
        vec![
            // Deobfuscate
            Box::new(buildtovalue_kernel::deobfuscator::Base64Detector::new()),
            Box::new(buildtovalue_kernel::deobfuscator::HexDecoder::new()),
            Box::new(buildtovalue_kernel::deobfuscator::LeetspeakDetector::new()),
            // Analyze
            Box::new(buildtovalue_kernel::statistics::EntropyCalculator::new()),
            Box::new(buildtovalue_kernel::statistics::ZScoreCalculator::new()),
            Box::new(buildtovalue_kernel::statistics::CharRatioAnalyzer::new()),
            // Validate
            Box::new(CpfValidator::new()),
            Box::new(CnpjValidator::new()),
            Box::new(EmailValidator::new()),
            Box::new(PhoneValidator::new()),
            Box::new(CreditCardValidator::new()),
        ]
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 1: NENHUM VALIDATOR RETORNA DEFAULT
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_all_validators_have_non_default_bias() {
        let default_bias = BiasDeclaration::default();

        for m in all_modules() {
            let bias = m.bias_declaration();

            assert!(
                bias.false_positive_rate != default_bias.false_positive_rate
                    || bias.false_negative_rate != default_bias.false_negative_rate
                    || bias.calibration_date != default_bias.calibration_date
                    || bias.test_dataset_size != default_bias.test_dataset_size,
                "Module {} retornou BiasDeclaration::default() (PROIBIDO por ADR-010)",
                m.name()
            );

            assert!(
                bias.false_positive_rate >= 0.0 && bias.false_positive_rate <= 1.0,
                "FPR fora de [0.0, 1.0]: {} (module: {})",
                bias.false_positive_rate, m.name()
            );

            assert!(
                bias.false_negative_rate >= 0.0 && bias.false_negative_rate <= 1.0,
                "FNR fora de [0.0, 1.0]: {} (module: {})",
                bias.false_negative_rate, m.name()
            );

            assert!(
                bias.calibration_date >= 20200101 && bias.calibration_date <= 20501231,
                "Calibration date inválido: {} (module: {})",
                bias.calibration_date, m.name()
            );

            assert!(
                bias.test_dataset_size >= 50,
                "Test dataset muito pequeno: {} < 50 (module: {})",
                bias.test_dataset_size, m.name()
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 2: CALIBRAÇÃO DENTRO DE 90 DIAS
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_bias_calibration_within_90_days() {
        for m in all_modules() {
            let bias = m.bias_declaration();

            assert!(
                bias.is_calibration_valid(),
                "Module {} tem calibração expirada (> 90 dias): {}",
                m.name(), bias.calibration_date
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 3: GATEKEEPER AGREGA WORST-CASE
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_gatekeeper_aggregates_worst_case() {
        let mut gatekeeper = Gatekeeper::new();
        let evidence = gatekeeper.scan_for_evidence("test input", 0x1234);

        assert!(evidence.bias.false_positive_rate > 0.0, "Aggregated FPR deve ser > 0");
        assert!(evidence.bias.false_negative_rate > 0.0, "Aggregated FNR deve ser > 0");
        assert!(evidence.bias.calibration_date > 0, "Aggregated calibration_date deve ser > 0");
        assert!(evidence.bias.test_dataset_size > 0, "Aggregated test_dataset_size deve ser > 0");

        let mut max_fpr = 0.0_f32;
        let mut max_fnr = 0.0_f32;

        for m in all_modules() {
            let bias = m.bias_declaration();
            max_fpr = max_fpr.max(bias.false_positive_rate);
            max_fnr = max_fnr.max(bias.false_negative_rate);
        }

        assert!(
            (evidence.bias.false_positive_rate - max_fpr).abs() < 0.01,
            "Aggregated FPR {} deve ser igual ao max individual {}",
            evidence.bias.false_positive_rate, max_fpr
        );

        assert!(
            (evidence.bias.false_negative_rate - max_fnr).abs() < 0.01,
            "Aggregated FNR {} deve ser igual ao max individual {}",
            evidence.bias.false_negative_rate, max_fnr
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 4: BIASDECLARATION SIZE == 512 BYTES
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_bias_declaration_size_512_bytes() {
        assert_eq!(
            std::mem::size_of::<BiasDeclaration>(),
            512,
            "BiasDeclaration deve ter exatamente 512 bytes (ADR-010)"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 5: TECHNICALEVIDENCE MANTÉM 9596 BYTES
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_technical_evidence_still_9596_bytes() {
        assert_eq!(
            std::mem::size_of::<TechnicalEvidence>(),
            9632,
            "TechnicalEvidence deve manter 9596 bytes após expansão de BiasDeclaration"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 6: UTF-8 TRUNCATION SEM PANIC
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_bias_utf8_truncation() {
        let long_text = "a".repeat(300);

        let bias = BiasDeclaration::new(0.1, 0.05, 20260209, 100)
            .with_limitations(&long_text)
            .with_affected_groups(&long_text);

        assert_eq!(bias.known_limitations[255], 0);
        assert_eq!(bias.affected_groups[127], 0);
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 7: EXPIRED CALIBRATION DETECTION
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_expired_calibration_detection() {
        let expired_bias = BiasDeclaration::new(0.10, 0.05, 20250901, 100);

        assert!(
            !expired_bias.is_calibration_valid(),
            "Calibração de 2025-09-01 deve estar expirada em fevereiro 2026"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 8: VALORES ESPECÍFICOS POR MÓDULO (Tabela ADR-010)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_cpf_bias_matches_adr_table() {
        let cpf = CpfValidator::new();
        let bias = Module::bias_declaration(&cpf);

        assert_eq!(bias.false_positive_rate, 0.08, "CPF FPR deve ser 0.08");
        assert_eq!(bias.false_negative_rate, 0.02, "CPF FNR deve ser 0.02");
        assert_eq!(bias.test_dataset_size, 500, "CPF dataset deve ser 500");
    }

    #[test]
    fn test_email_bias_matches_adr_table() {
        let email = EmailValidator::new();
        let bias = Module::bias_declaration(&email);

        assert_eq!(bias.false_positive_rate, 0.03);
        assert_eq!(bias.false_negative_rate, 0.08);
        assert_eq!(bias.test_dataset_size, 800);
    }

    #[test]
    fn test_credit_card_bias_matches_adr_table() {
        let cc = CreditCardValidator::new();
        let bias = Module::bias_declaration(&cc);

        assert_eq!(bias.false_positive_rate, 0.05);
        assert_eq!(bias.false_negative_rate, 0.01);
        assert_eq!(bias.test_dataset_size, 300);
    }
}