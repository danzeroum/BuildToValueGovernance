
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Regex simplificado (RFC 5322 completo é muito complexo)
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
            // Email é Medium (não tão sensível quanto CPF)
            severity: TechnicalSeverity::Medium,
        }
    }
    
    pub fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for mat in EMAIL_REGEX.find_iter(input) {
            let matched = mat.as_str();
            
            // Validações adicionais
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
                .with_confidence(200);  // 78% (regex pode ter FPs)
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    fn is_plausible_email(email: &str) -> bool {
        // Validações básicas
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }
        
        let local = parts[0];
        let domain = parts [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/a8bf2d44-ead0-43f2-99b4-cf572fdbfb91/paste.txt);
        
        // Local part não pode estar vazio
        if local.is_empty() || domain.is_empty() {
            return false;
        }
        
        // Domain deve ter pelo menos um ponto
        if !domain.contains('.') {
            return false;
        }
        
        // Não deve terminar com ponto
        if domain.ends_with('.') {
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