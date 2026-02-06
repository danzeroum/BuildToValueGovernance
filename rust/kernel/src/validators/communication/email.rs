// Padrão para todos os validadores
use crate::evidence::finding::Finding;
use crate::core::types::{ValidatorModule, TechnicalSeverity};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Regex simplificado para detecção de e-mails
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ).unwrap();
}

pub struct EmailValidator {
    rule_id: String,
    severity: TechnicalSeverity,
}

impl EmailValidator {
    pub fn new() -> Self {
        Self {
            rule_id: "VALIDATORS_EMAIL_001".to_string(),
            // Email é classificado como Medium (PII padrão)
            severity: TechnicalSeverity::Medium,
        }
    }

    pub fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in EMAIL_REGEX.find_iter(input) {
            let matched = mat.as_str();

            // Validações adicionais de plausibilidade
            if Self::is_plausible_email(matched) {
                let finding = Finding::new(
                    ValidatorModule::Email,
                    self.severity,
                    &self.rule_id,
                    "EMAIL_PATTERN_DETECTED",
                    "Email address pattern found in input",
                )
                    .with_matched_text(matched)
                    .with_position(mat.start() as u16, mat.end() as u16)
                    .with_confidence(200);  // ~78% de confiança

                findings.push(finding);
            }
        }

        findings
    }

    fn is_plausible_email(email: &str) -> bool {
        // Validações básicas de estrutura
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        let local = parts[0];
        let domain = parts[1]; // ✅ CORRIGIDO: Removida URL corrompida

        // Parte local e domínio não podem estar vazios
        if local.is_empty() || domain.is_empty() {
            return false;
        }

        // Domínio deve ter pelo menos um ponto e não terminar com ele
        if !domain.contains('.') || domain.ends_with('.') {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        let validator = EmailValidator::new();
        let findings = validator.validate("Contato: joao@exemplo.com.br");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, TechnicalSeverity::Medium);
    }

    #[test]
    fn test_invalid_email() {
        let validator = EmailValidator::new();
        let findings = validator.validate("@exemplo.com");
        assert_eq!(findings.len(), 0);
    }
}