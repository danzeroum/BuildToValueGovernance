//! Credit Card Validator (Luhn Algorithm)
//!
//! Detecta números de cartão de crédito via Luhn checksum.
//!
//! Suporta:
//! - Visa (13, 16 dígitos)
//! - Mastercard (16 dígitos)
//! - Amex (15 dígitos)
//! - Diners (14 dígitos)
//!
//! Gate: Week 3 - Day 12

use super::{Validator, ValidationResult};
use regex::Regex;
use once_cell::sync::Lazy;

static CC_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Detecta sequências de 13-16 dígitos (com espaços/hífens opcionais)
    Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b").unwrap()
});

pub struct CreditCardValidator;

impl CreditCardValidator {
    /// Normaliza número de cartão
    fn normalize(cc: &str) -> String {
        cc.chars().filter(|c| c.is_ascii_digit()).collect()
    }
    
    /// Valida via Luhn Algorithm
    ///
    /// Algoritmo:
    /// 1. Da direita para esquerda, dobra cada segundo dígito
    /// 2. Se resultado > 9, subtrai 9
    /// 3. Soma todos os dígitos
    /// 4. Válido se soma % 10 == 0
    fn validate_luhn(cc: &str) -> bool {
        let digits: Vec<u32> = cc
            .chars()
            .filter_map(|c| c.to_digit(10))
            .collect();
        
        // 13-19 dígitos (range padrão de cartões)
        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }
        
        let sum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &d)| {
                if i % 2 == 1 {
                    // Dobra cada segundo dígito
                    let doubled = d * 2;
                    if doubled > 9 {
                        doubled - 9
                    } else {
                        doubled
                    }
                } else {
                    d
                }
            })
            .sum();
        
        sum % 10 == 0
    }
    
    /// Identifica bandeira do cartão
    fn identify_brand(cc: &str) -> &'static str {
        if cc.starts_with('4') {
            "Visa"
        } else if cc.starts_with('5') {
            "Mastercard"
        } else if cc.starts_with("34") || cc.starts_with("37") {
            "Amex"
        } else if cc.starts_with("36") || cc.starts_with("38") {
            "Diners"
        } else {
            "Unknown"
        }
    }
}

impl Validator for CreditCardValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        for capture in CC_REGEX.find_iter(input) {
            let cc_raw = capture.as_str();
            let cc_normalized = Self::normalize(cc_raw);
            
            if Self::validate_luhn(&cc_normalized) {
                let brand = Self::identify_brand(&cc_normalized);
                
                return Some(ValidationResult {
                    validator_name: name.to_string(),
                    is_violation: true,
                    message: format!("Valid credit card detected: {} ({})", cc_raw, brand),
                    category: "financial".to_string(),
                    location: format!("offset {}", capture.start()),
                    evidence: format!("{}****{}", &cc_raw[..4], &cc_raw[cc_raw.len()-4..]),
                    severity: 0.95, // CRITICAL
                    confidence: 0.95,
                });
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_luhn_valid() {
        // Visa test card
        assert!(CreditCardValidator::validate_luhn("4532015112830366"));
        
        // Mastercard test card
        assert!(CreditCardValidator::validate_luhn("5425233430109903"));
    }
    
    #[test]
    fn test_luhn_invalid() {
        assert!(!CreditCardValidator::validate_luhn("1234567890123456"));
    }
    
    #[test]
    fn test_brand_detection() {
        assert_eq!(CreditCardValidator::identify_brand("4532015112830366"), "Visa");
        assert_eq!(CreditCardValidator::identify_brand("5425233430109903"), "Mastercard");
        assert_eq!(CreditCardValidator::identify_brand("378282246310005"), "Amex");
    }
}
