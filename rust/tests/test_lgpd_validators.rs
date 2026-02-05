// BuildToValue v2.0 - LGPD Validators Integration Tests
//
// Tests Rust validators for LGPD compliance

#[cfg(test)]
mod tests {
    use buildtovalue::validators::{
        ConsentValidator, ConsentRevocationValidator, SensitiveDataValidator, Validator,
    };
    use std::collections::HashMap;

    // ═══════════════════════════════════════════════════════════════════
    // CONSENT VALIDATOR TESTS
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_consent_validator_missing_consent() {
        let validator = ConsentValidator::default();
        let mut metadata = HashMap::new();
        metadata.insert("user.has_consent".to_string(), "false".to_string());
        metadata.insert("processing.requires_consent".to_string(), "true".to_string());

        let findings = validator.validate("", Some(&metadata));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "LGPD_ART7_I_CONSENTIMENTO");
        assert_eq!(findings[0].title, "MISSING_USER_CONSENT");
        assert_eq!(findings[0].confidence, 255);
    }

    #[test]
    fn test_consent_validator_with_legal_basis() {
        let validator = ConsentValidator::default();
        let mut metadata = HashMap::new();
        metadata.insert("user.has_consent".to_string(), "false".to_string());
        metadata.insert("processing.requires_consent".to_string(), "true".to_string());
        metadata.insert(
            "processing.legal_basis".to_string(),
            "legitimate_interest".to_string(),
        );

        let findings = validator.validate("", Some(&metadata));

        // Should have no findings (has alternative legal basis)
        assert_eq!(findings.len(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════
    // CONSENT REVOCATION VALIDATOR TESTS
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_consent_revocation_processing_continues() {
        let validator = ConsentRevocationValidator;
        let mut metadata = HashMap::new();
        metadata.insert("user.consent_revoked".to_string(), "true".to_string());
        metadata.insert("processing.continues".to_string(), "true".to_string());

        let findings = validator.validate("", Some(&metadata));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "LGPD_ART8_P5_REVOGACAO");
        assert_eq!(findings[0].confidence, 255);
    }

    #[test]
    fn test_consent_revocation_processing_stopped() {
        let validator = ConsentRevocationValidator;
        let mut metadata = HashMap::new();
        metadata.insert("user.consent_revoked".to_string(), "true".to_string());
        metadata.insert("processing.continues".to_string(), "false".to_string());

        let findings = validator.validate("", Some(&metadata));

        assert_eq!(findings.len(), 0); // Compliant
    }

    // ═══════════════════════════════════════════════════════════════════
    // SENSITIVE DATA VALIDATOR TESTS
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_sensitive_data_health() {
        let validator = SensitiveDataValidator::default();
        let input = "Paciente tem diagnóstico de diabetes";

        let findings = validator.validate(input, None);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "LGPD_ART11_DADOS_SENSIVEIS");
        assert!(findings[0].title.contains("HEALTH"));
    }

    #[test]
    fn test_sensitive_data_biometric() {
        let validator = SensitiveDataValidator::default();
        let input = "Realizar reconhecimento facial";

        let findings = validator.validate(input, None);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("BIOMETRIC"));
    }

    #[test]
    fn test_sensitive_data_with_consent() {
        let validator = SensitiveDataValidator::default();
        let input = "Paciente tem HIV";

        let mut metadata = HashMap::new();
        metadata.insert(
            "consent.is_specific_for_sensitive".to_string(),
            "true".to_string(),
        );

        let findings = validator.validate(input, Some(&metadata));

        assert_eq!(findings.len(), 0); // Has specific consent
    }

    #[test]
    fn test_sensitive_data_religious() {
        let validator = SensitiveDataValidator::default();
        let input = "Candidato declarou religião evangélica";

        let findings = validator.validate(input, None);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("RELIGIOUS"));
    }

    #[test]
    fn test_no_sensitive_data() {
        let validator = SensitiveDataValidator::default();
        let input = "Nome: João, Endereço: Rua A";

        let findings = validator.validate(input, None);

        assert_eq!(findings.len(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════
    // BIAS DECLARATION TESTS
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_consent_validator_bias_declaration() {
        let validator = ConsentValidator::default();
        let bias = validator.bias_declaration();

        assert_eq!(bias.false_positive_rate, 0.05);
        assert_eq!(bias.false_negative_rate, 0.02);
        assert_eq!(bias.calibration_date, "2026-02-05");
        assert!(bias.known_limitations.len() > 0);
    }

    #[test]
    fn test_sensitive_data_validator_bias_declaration() {
        let validator = SensitiveDataValidator::default();
        let bias = validator.bias_declaration();

        assert_eq!(bias.false_positive_rate, 0.18);
        assert_eq!(bias.false_negative_rate, 0.12);
        assert!(bias.test_dataset_size > 0);
    }
}
