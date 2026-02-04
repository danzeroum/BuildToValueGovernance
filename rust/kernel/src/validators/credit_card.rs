
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Detecta sequências de 13-19 dígitos (com ou sem espaços/hífens)
    static ref CARD_REGEX: Regex = Regex::new(
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4,7}\b"
    ).unwrap();
}

/// Validator de cartão de crédito usando Algoritmo de Luhn
pub struct CreditCardValidator {
    rule_id: String,
}

impl CreditCardValidator {
    pub fn new() -> Self {
        Self {
            rule_id: "VALIDATORS_LUHN_001".to_string(),
        }
    }
    
    pub fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for mat in CARD_REGEX.find_iter(input) {
            let matched = mat.as_str();
            let cleaned = Self::clean_card_number(matched);
            
            // Valida comprimento (13-19 dígitos)
            if cleaned.len() < 13 || cleaned.len() > 19 {
                continue;
            }
            
            // Valida Luhn checksum
            if Self::is_valid_luhn(&cleaned) {
                // Identifica bandeira
                let brand = Self::identify_brand(&cleaned);
                
                let finding = Finding::new(
                    ValidatorModule::CreditCard,
                    TechnicalSeverity::Critical,  // Cartão é CRÍTICO
                    &self.rule_id,
                    "CREDIT_CARD_DETECTED",
                    &format!("Possible {} card number detected", brand),
                )
                .with_matched_text(matched)
                .with_position(mat.start() as u16, mat.end() as u16)
                .with_confidence(240);  // 94% (Luhn pode ter FPs em sequências aleatórias)
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    fn clean_card_number(card: &str) -> String {
        card.chars()
            .filter(|c| c.is_numeric())
            .collect()
    }
    
    /// Algoritmo de Luhn (validação de dígito verificador)
    fn is_valid_luhn(number: &str) -> bool {
        let digits: Vec<u32> = number.chars()
            .filter_map(|c| c.to_digit(10))
            .collect();
        
        if digits.is_empty() {
            return false;
        }
        
        let mut sum = 0;
        let mut alternate = false;
        
        // Processa da direita para esquerda
        for &digit in digits.iter().rev() {
            let mut n = digit;
            
            if alternate {
                n *= 2;
                if n > 9 {
                    n -= 9;
                }
            }
            
            sum += n;
            alternate = !alternate;
        }
        
        sum % 10 == 0
    }
    
    /// Identifica bandeira do cartão (BIN - Bank Identification Number)
    fn identify_brand(number: &str) -> &'static str {
        if number.starts_with('4') {
            "Visa"
        } else if number.starts_with("51") || number.starts_with("52") || 
                  number.starts_with("53") || number.starts_with("54") || 
                  number.starts_with("55") {
            "Mastercard"
        } else if number.starts_with("34") || number.starts_with("37") {
            "American Express"
        } else if number.starts_with("6011") || number.starts_with("65") {
            "Discover"
        } else if number.starts_with("35") {
            "JCB"
        } else {
            "Unknown"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_visa() {
        let validator = CreditCardValidator::new();
        // Número de teste Visa (não funcional)
        let findings = validator.validate("4532015112830366");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, TechnicalSeverity::Critical);
    }
    
    #[test]
    fn test_luhn_algorithm() {
        assert!(CreditCardValidator::is_valid_luhn("4532015112830366"));
        assert!(!CreditCardValidator::is_valid_luhn("4532015112830367"));
    }
    
    #[test]
    fn test_brand_identification() {
        assert_eq!(CreditCardValidator::identify_brand("4532"), "Visa");
        assert_eq!(CreditCardValidator::identify_brand("5105"), "Mastercard");
        assert_eq!(CreditCardValidator::identify_brand("3782"), "American Express");
    }
}