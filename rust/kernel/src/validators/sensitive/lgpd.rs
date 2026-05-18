//! Sensitive Data Validator v2.4.0
//! Detecta dados sensíveis segundo LGPD Art. 11.

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref HEALTH_PATTERN_1: Regex =
        Regex::new(r"(?i)\b(diabetes|câncer|HIV|AIDS|hepatite|tuberculose)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in HEALTH_PATTERN_1: {e}"));
    static ref HEALTH_PATTERN_2: Regex =
        Regex::new(r"(?i)\b(doença|diagnóstico|tratamento|cirurgia|medicamento)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in HEALTH_PATTERN_2: {e}"));
    static ref BIOMETRIC_PATTERN_1: Regex =
        Regex::new(r"(?i)\b(biometria|impressão digital|reconhecimento facial)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in BIOMETRIC_PATTERN_1: {e}"));
    static ref BIOMETRIC_PATTERN_2: Regex =
        Regex::new(r"(?i)\b(iris|retina|DNA|genético|genoma)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in BIOMETRIC_PATTERN_2: {e}"));
    static ref RACIAL_PATTERN: Regex =
        Regex::new(r"(?i)\b(raça|cor|etnia|pardo|negro|branco|indígena)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in RACIAL_PATTERN: {e}"));
    static ref RELIGIOUS_PATTERN: Regex =
        Regex::new(r"(?i)\b(religião|crença|católico|protestante|espírita|ateu)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in RELIGIOUS_PATTERN: {e}"));
    static ref POLITICAL_PATTERN: Regex =
        Regex::new(r"(?i)\b(partido político|filiação partidária|ideologia)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in POLITICAL_PATTERN: {e}"));
    static ref SEXUAL_PATTERN: Regex =
        Regex::new(r"(?i)\b(orientação sexual|homossexual|heterossexual|bissexual)\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in SEXUAL_PATTERN: {e}"));
}

pub struct SensitiveDataValidator;

impl SensitiveDataValidator {
    pub fn new() -> Self {
        Self
    }

    fn detect_sensitive_type(&self, input: &str) -> Vec<(String, f32)> {
        let mut detections = Vec::new();
        if HEALTH_PATTERN_1.is_match(input) || HEALTH_PATTERN_2.is_match(input) {
            detections.push(("health".to_string(), 0.95));
        }
        if BIOMETRIC_PATTERN_1.is_match(input) || BIOMETRIC_PATTERN_2.is_match(input) {
            detections.push(("biometric".to_string(), 0.97));
        }
        if RACIAL_PATTERN.is_match(input) {
            detections.push(("racial".to_string(), 0.85));
        }
        if RELIGIOUS_PATTERN.is_match(input) {
            detections.push(("religious".to_string(), 0.88));
        }
        if POLITICAL_PATTERN.is_match(input) {
            detections.push(("political".to_string(), 0.82));
        }
        if SEXUAL_PATTERN.is_match(input) {
            detections.push(("sexual_orientation".to_string(), 0.90));
        }
        detections
    }

    pub fn name(&self) -> &'static str { "sensitive_data_validator" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::SensitiveData }
}

impl Default for SensitiveDataValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for SensitiveDataValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let detections = self.detect_sensitive_type(input);
        for (data_type, conf) in detections {
            findings.push(
                Finding::new(
                    ValidatorModule::SensitiveData,
                    TechnicalSeverity::Critical(255),
                    "LGPD_ART11_DADOS_SENSIVEIS",
                    &format!("SENSITIVE_DATA_{}", data_type.to_uppercase()),
                    input,
                )
                    .with_confidence((conf * 255.0) as u8)
            );
        }
        findings
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.18, 0.12, 20260517, 200)
            .with_limitations(
                "Keyword-based detection (no semantics); Brazilian Portuguese only; high FPR for medical terms."
            )
            .with_affected_groups(
                "Medical research contexts; cultural ambiguity in racial terms."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_data_detected() {
        let v = SensitiveDataValidator::new();
        let findings = v.validate("Paciente João Silva tem diagnóstico de diabetes tipo 2");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_sensitive_data() {
        let v = SensitiveDataValidator::new();
        let findings = v.validate("Nome: João Silva, Endereço: Rua A, 123");
        assert_eq!(findings.len(), 0);
    }
}
