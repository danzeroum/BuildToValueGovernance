
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Regex para telefones brasileiros
    // Formatos: (11) 98765-4321, 11987654321, +55 11 98765-4321
    static ref PHONE_REGEX: Regex = Regex::new(
        r"(?:\+55\s?)?(?:\(?\d{2}\)?[\s-]?)?\d{4,5}[\s-]?\d{4}"
    ).unwrap();
}

pub struct PhoneValidator {
    rule_id: String,
}

impl PhoneValidator {
    pub fn new() -> Self {
        Self {
            rule_id: "VALIDATORS_PHONE_001".to_string(),
        }
    }
    
    pub fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for mat in PHONE_REGEX.find_iter(input) {
            let matched = mat.as_str();
            let cleaned = Self::clean_phone(matched);
            
            // Valida se tem 10 ou 11 dígitos (com ou sem DDI)
            let digit_count = cleaned.len();
            if (digit_count == 10 || digit_count == 11 || 
                digit_count == 12 || digit_count == 13) {
                
                // Severidade menor que CPF (telefone não é PII crítico)
                let finding = Finding::new(
                    ValidatorModule::Phone,
                    TechnicalSeverity::Low,
                    &self.rule_id,
                    "PHONE_PATTERN_DETECTED",
                    "Brazilian phone number pattern detected",
                )
                .with_matched_text(matched)
                .with_position(mat.start() as u16, mat.end() as u16)
                .with_confidence(180);  // 70% (muitos falsos positivos)
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    fn clean_phone(phone: &str) -> String {
        phone.chars()
            .filter(|c| c.is_numeric())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mobile_phone() {
        let validator = PhoneValidator::new();
        let findings = validator.validate("Celular: (11) 98765-4321");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, TechnicalSeverity::Low);
    }
    
    #[test]
    fn test_landline() {
        let validator = PhoneValidator::new();
        let findings = validator.validate("Tel: (11) 3456-7890");
        assert_eq!(findings.len(), 1);
    }
}