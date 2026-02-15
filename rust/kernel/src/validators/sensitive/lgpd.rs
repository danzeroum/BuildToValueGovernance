//! Sensitive Data Validator v2.4.0
//! Detecta dados sensíveis segundo LGPD Art. 11.

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;
use regex::Regex;

pub struct SensitiveDataValidator {
    health_patterns: Vec<Regex>,
    biometric_patterns: Vec<Regex>,
    racial_patterns: Vec<Regex>,
    religious_patterns: Vec<Regex>,
    political_patterns: Vec<Regex>,
    sexual_patterns: Vec<Regex>,
}

impl Default for SensitiveDataValidator {
    fn default() -> Self {
        Self {
            health_patterns: vec![
                Regex::new(r"(?i)\b(diabetes|câncer|HIV|AIDS|hepatite|tuberculose)\b").unwrap(),
                Regex::new(r"(?i)\b(doença|diagnóstico|tratamento|cirurgia|medicamento)\b").unwrap(),
            ],
            biometric_patterns: vec![
                Regex::new(r"(?i)\b(biometria|impressão digital|reconhecimento facial)\b").unwrap(),
                Regex::new(r"(?i)\b(iris|retina|DNA|genético|genoma)\b").unwrap(),
            ],
            racial_patterns: vec![
                Regex::new(r"(?i)\b(raça|cor|etnia|pardo|negro|branco|indígena)\b").unwrap(),
            ],
            religious_patterns: vec![
                Regex::new(r"(?i)\b(religião|crença|católico|protestante|espírita|ateu)\b").unwrap(),
            ],
            political_patterns: vec![
                Regex::new(r"(?i)\b(partido político|filiação partidária|ideologia)\b").unwrap(),
            ],
            sexual_patterns: vec![
                Regex::new(r"(?i)\b(orientação sexual|homossexual|heterossexual|bissexual)\b").unwrap(),
            ],
        }
    }
}

impl SensitiveDataValidator {
    pub fn new() -> Self {
        Self::default()
    }

    fn detect_sensitive_type(&self, input: &str) -> Vec<(String, f32)> {
        let mut detections = Vec::new();
        if self.health_patterns.iter().any(|p| p.is_match(input)) {
            detections.push(("health".to_string(), 0.95));
        }
        if self.biometric_patterns.iter().any(|p| p.is_match(input)) {
            detections.push(("biometric".to_string(), 0.97));
        }
        if self.racial_patterns.iter().any(|p| p.is_match(input)) {
            detections.push(("racial".to_string(), 0.85));
        }
        if self.religious_patterns.iter().any(|p| p.is_match(input)) {
            detections.push(("religious".to_string(), 0.88));
        }
        if self.political_patterns.iter().any(|p| p.is_match(input)) {
            detections.push(("political".to_string(), 0.82));
        }
        if self.sexual_patterns.iter().any(|p| p.is_match(input)) {
            detections.push(("sexual_orientation".to_string(), 0.90));
        }
        detections
    }

    pub fn name(&self) -> &'static str { "sensitive_data_validator" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::SensitiveData }
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
                    input,  // contexto completo; em produção podemos truncar
                )
                    .with_confidence((conf * 255.0) as u8)
            );
        }
        findings
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.18, 0.12, 20260209, 200)
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
        // assert!(findings[0].threat_category().contains("HEALTH"));
    }

    #[test]
    fn test_no_sensitive_data() {
        let v = SensitiveDataValidator::new();
        let findings = v.validate("Nome: João Silva, Endereço: Rua A, 123");
        assert_eq!(findings.len(), 0);
    }
}