//! Testes Obrigatórios ADR-010: BiasDeclaration Mandate
//!
//! Verifica conformidade de TODOS os validators com ADR-010 v1.5.0
//!
//! FILOSOFIA (Jonas, 1984 - Princípio da Responsabilidade):
//! - Transparência sobre limitações é obrigação ética, não feature opcional
//! - Testes garantem que NENHUM validator retorna BiasDeclaration::default()
//! - Calibrações expiradas (> 90 dias) DEVEM ser detectadas

use buildtovalue_kernel::core::types::BiasDeclaration;
use buildtovalue_kernel::validators::{
    Validator,
    brazilian::{CpfValidator, CnpjValidator},
    communication::{EmailValidator, PhoneValidator},
    financial::CreditCardValidator,
};
use buildtovalue_kernel::gatekeeper::Gatekeeper;
use buildtovalue_kernel::evidence::TechnicalEvidence;

// ═══════════════════════════════════════════════════════════════════════════
// TEST 1: NENHUM VALIDATOR RETORNA DEFAULT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_all_validators_have_non_default_bias() {
    let validators: Vec<Box<dyn Validator>> = vec![
        Box::new(CpfValidator::new()),
        Box::new(CnpjValidator::new()),
        Box::new(EmailValidator::new()),
        Box::new(PhoneValidator::new()),
        Box::new(CreditCardValidator::new()),
    ];

    let default_bias = BiasDeclaration::default();

    for v in validators {
        let bias = v.bias_declaration();

        // PROIBIDO retornar default em produção
        assert!(
            bias.false_positive_rate != default_bias.false_positive_rate ||
                bias.false_negative_rate != default_bias.false_negative_rate ||
                bias.calibration_date != default_bias.calibration_date ||
                bias.test_dataset_size != default_bias.test_dataset_size,
            "Validator {} retornou BiasDeclaration::default() (PROIBIDO por ADR-010)",
            v.name()
        );

        // FPR e FNR devem estar entre 0.0 e 1.0
        assert!(
            bias.false_positive_rate >= 0.0 && bias.false_positive_rate <= 1.0,
            "FPR fora do intervalo [0.0, 1.0]: {} (validator: {})",
            bias.false_positive_rate, v.name()
        );

        assert!(
            bias.false_negative_rate >= 0.0 && bias.false_negative_rate <= 1.0,
            "FNR fora do intervalo [0.0, 1.0]: {} (validator: {})",
            bias.false_negative_rate, v.name()
        );

        // Calibration date deve ser válido (formato YYYYMMDD)
        assert!(
            bias.calibration_date >= 20200101 && bias.calibration_date <= 20501231,
            "Calibration date inválido: {} (validator: {})",
            bias.calibration_date, v.name()
        );

        // Test dataset deve ter pelo menos 50 amostras
        assert!(
            bias.test_dataset_size >= 50,
            "Test dataset muito pequeno: {} < 50 (validator: {})",
            bias.test_dataset_size, v.name()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 2: CALIBRAÇÃO DENTRO DE 90 DIAS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_bias_calibration_within_90_days() {
    let validators: Vec<Box<dyn Validator>> = vec![
        Box::new(CpfValidator::new()),
        Box::new(CnpjValidator::new()),
        Box::new(EmailValidator::new()),
        Box::new(PhoneValidator::new()),
        Box::new(CreditCardValidator::new()),
    ];

    for v in validators {
        let bias = v.bias_declaration();

        assert!(
            bias.is_calibration_valid(),
            "Validator {} tem calibração expirada (> 90 dias): {}",
            v.name(), bias.calibration_date
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 3: GATEKEEPER AGREGA WORST-CASE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_gatekeeper_aggregates_worst_case() {
    let mut gatekeeper = Gatekeeper::new();
    let evidence = gatekeeper.scan_for_evidence("test input", 0x1234);

    // Gatekeeper deve agregar BiasDeclaration
    assert!(evidence.bias.false_positive_rate > 0.0, "Aggregated FPR deve ser > 0");
    assert!(evidence.bias.false_negative_rate > 0.0, "Aggregated FNR deve ser > 0");
    assert!(evidence.bias.calibration_date > 0, "Aggregated calibration_date deve ser > 0");
    assert!(evidence.bias.test_dataset_size > 0, "Aggregated test_dataset_size deve ser > 0");

    // Worst-case: FPR/FNR agregado deve ser >= maior individual
    let validators: Vec<Box<dyn Validator>> = vec![
        Box::new(CpfValidator::new()),
        Box::new(CnpjValidator::new()),
        Box::new(EmailValidator::new()),
        Box::new(PhoneValidator::new()),
        Box::new(CreditCardValidator::new()),
    ];

    let mut max_individual_fpr = 0.0_f32;
    let mut max_individual_fnr = 0.0_f32;

    for v in validators {
        let bias = v.bias_declaration();
        max_individual_fpr = max_individual_fpr.max(bias.false_positive_rate);
        max_individual_fnr = max_individual_fnr.max(bias.false_negative_rate);
    }

    // Princípio da Precaução (Jonas): worst-case propagation
    assert!(
        (evidence.bias.false_positive_rate - max_individual_fpr).abs() < 0.01,
        "Aggregated FPR {} deve ser igual ao max individual {}",
        evidence.bias.false_positive_rate, max_individual_fpr
    );

    assert!(
        (evidence.bias.false_negative_rate - max_individual_fnr).abs() < 0.01,
        "Aggregated FNR {} deve ser igual ao max individual {}",
        evidence.bias.false_negative_rate, max_individual_fnr
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 4: BIASDECLARATION SIZE == 512 BYTES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_bias_declaration_size_512_bytes() {
    assert_eq!(
        std::mem::size_of::<BiasDeclaration>(),
        512,
        "BiasDeclaration deve ter exatamente 512 bytes (ADR-010)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 5: TECHNICALEVIDENCE MANTÉM 9596 BYTES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_technical_evidence_still_9596_bytes() {
    assert_eq!(
        std::mem::size_of::<TechnicalEvidence>(),
        9596,
        "TechnicalEvidence deve manter 9596 bytes após expansão de BiasDeclaration"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 6: UTF-8 TRUNCATION SEM PANIC
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_bias_utf8_truncation() {
    let long_text = "a".repeat(300); // > 255 bytes

    let bias = BiasDeclaration::new(0.1, 0.05, 20260209, 100)
        .with_limitations(&long_text)
        .with_affected_groups(&long_text);

    // Não deve panizar, deve truncar
    assert_eq!(bias.known_limitations[255], 0); // Null terminator
    assert_eq!(bias.affected_groups[127], 0);   // Null terminator
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 7: EXPIRED CALIBRATION WARNING (Integration Test)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_expired_calibration_detection() {
    // Bias com data expirada (> 90 dias no passado)
    let expired_bias = BiasDeclaration::new(
        0.10,
        0.05,
        20250901, // ~5 meses atrás (fevereiro 2026)
        100
    );

    assert!(
        !expired_bias.is_calibration_valid(),
        "Calibração de 2025-09-01 deve estar expirada em fevereiro 2026"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 8: VALORES ESPECÍFICOS POR MÓDULO (Tabela ADR-010)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_cpf_bias_matches_adr_table() {
    let cpf = CpfValidator::new();
    let bias = cpf.bias_declaration();

    assert_eq!(bias.false_positive_rate, 0.08, "CPF FPR deve ser 0.08 (tabela ADR-010)");
    assert_eq!(bias.false_negative_rate, 0.02, "CPF FNR deve ser 0.02 (tabela ADR-010)");
    assert_eq!(bias.test_dataset_size, 500, "CPF dataset deve ser 500 (tabela ADR-010)");
}

#[test]
fn test_email_bias_matches_adr_table() {
    let email = EmailValidator::new();
    let bias = email.bias_declaration();

    assert_eq!(bias.false_positive_rate, 0.03);
    assert_eq!(bias.false_negative_rate, 0.08);
    assert_eq!(bias.test_dataset_size, 800);
}

#[test]
fn test_credit_card_bias_matches_adr_table() {
    let cc = CreditCardValidator::new();
    let bias = cc.bias_declaration();

    assert_eq!(bias.false_positive_rate, 0.05);
    assert_eq!(bias.false_negative_rate, 0.12);
    assert_eq!(bias.test_dataset_size, 200);
}
