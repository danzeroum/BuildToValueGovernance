
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref CNPJ_REGEX: Regex = Regex::new(
        r"(?:\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})"
    ).unwrap();
}

/// Validator de CNPJ (Cadastro Nacional de Pessoa Jurídica - Brasil)
pub struct CnpjValidator {
    rule_id: String,
}

impl CnpjValidator {
    pub fn new() -> Self {
        Self {
            rule_id: "VALIDATORS_CNPJ_001".to_string(),
        }
    }
    
    pub fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for mat in CNPJ_REGEX.find_iter(input) {
            let matched = mat.as_str();
            let cleaned = Self::clean_cnpj(matched);
            
            if Self::is_valid_cnpj(&cleaned) {
                let finding = Finding::new(
                    ValidatorModule::CNPJ,
                    TechnicalSeverity::PolicyViolation,
                    &self.rule_id,
                    "CNPJ_PATTERN_DETECTED",
                    "Valid CNPJ pattern found in input",
                )
                .with_matched_text(matched)
                .with_position(mat.start() as u16, mat.end() as u16)
                .with_confidence(255);
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    fn clean_cnpj(cnpj: &str) -> String {
        cnpj.chars().filter(|c| c.is_numeric()).collect()
    }
    
    fn is_valid_cnpj(cnpj: &str) -> bool {
        if cnpj.len() != 14 {
            return false;
        }
        
        // CNPJs inválidos (todos dígitos iguais)
        if cnpj.chars().all(|c| c == cnpj.chars().next().unwrap()) {
            return false;
        }
        
        let digits: Vec<u32> = cnpj.chars()
            .filter_map(|c| c.to_digit(10))
            .collect();
        
        if digits.len() != 14 {
            return false;
        }
        
        // Primeiro dígito verificador
        let weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        let mut sum = 0;
        for i in 0..12 {
            sum += digits[i] * weights1[i];
        }
        let remainder = sum % 11;
        let check1 = if remainder < 2 { 0 } else { 11 - remainder };
        
        if digits [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/14874737/b97d7118-4a2d-44fd-93a5-647504328129/paste.txt) != check1 {
            return false;
        }
        
        // Segundo dígito verificador
        let weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        sum = 0;
        for i in 0..13 {
            sum += digits[i] * weights2[i];
        }
        let remainder = sum % 11;
        let check2 = if remainder < 2 { 0 } else { 11 - remainder };
        
        digits [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/14874737/7469965b-43e7-44b9-b34d-7e4e815d81a7/paste.txt) == check2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_cnpj() {
        let validator = CnpjValidator::new();
        let findings = validator.validate("CNPJ: 11.222.333/0001-81");
        assert_eq!(findings.len(), 1);
    }
    
    #[test]
    fn test_invalid_cnpj() {
        let validator = CnpjValidator::new();
        let findings = validator.validate("11.222.333/0001-00");
        assert_eq!(findings.len(), 0);
    }
}