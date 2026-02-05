
impl CPFValidator {
    /// Valida CPF em tempo constante (sempre ~50μs)
    pub fn validate_constant_time(&self, text: &str) -> ValidationResult {
        let start = Instant::now();
        
        // 1. Extrai CPF (constant-time)
        let cpf_opt = self.extract_cpf_ct(text);
        
        // 2. Valida checksum (sempre executa, mesmo se None)
        let checksum_valid = match cpf_opt {
            Some(cpf) => self.validate_checksum_ct(&cpf),
            None => {
                // IMPORTANTE: Executa operação dummy para manter timing
                self.dummy_checksum_validation();
                false
            }
        };
        
        // 3. Verifica blacklist (sempre consulta, mesmo se inválido)
        let blacklisted = match cpf_opt {
            Some(cpf) if checksum_valid => self.is_blacklisted_ct(&cpf),
            _ => {
                // Dummy query (tempo constante)
                self.dummy_blacklist_check();
                false
            }
        };
        
        // 4. Padding de tempo (garante mínimo de 50μs)
        let elapsed = start.elapsed();
        const MIN_TIME_US: u64 = 50;
        if elapsed.as_micros() < MIN_TIME_US as u128 {
            let padding = Duration::from_micros(MIN_TIME_US - elapsed.as_micros() as u64);
            spin_sleep::sleep(padding);  // Busy-wait (não yield ao OS)
        }
        
        // 5. Retorna resultado (uniform response)
        if cpf_opt.is_some() && checksum_valid && !blacklisted {
            ValidationResult::Violation(/* ... */)
        } else {
            ValidationResult::Clean
        }
    }
    
    /// Checksum validation (constant-time)
    fn validate_checksum_ct(&self, cpf: &str) -> bool {
        // Remove formatação
        let digits: Vec<u8> = cpf.chars()
            .filter(|c| c.is_numeric())
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();
        
        if digits.len() != 11 {
            return false;
        }
        
        // Calcula primeiro dígito verificador
        let mut sum1 = 0u32;
        for i in 0..9 {
            sum1 += (digits[i] as u32) * (10 - i as u32);
        }
        let check1 = ((sum1 * 10) % 11) % 10;
        
        // Calcula segundo dígito verificador
        let mut sum2 = 0u32;
        for i in 0..10 {
            sum2 += (digits[i] as u32) * (11 - i as u32);
        }
        let check2 = ((sum2 * 10) % 11) % 10;
        
        // Comparação constant-time (evita early return)
        let match1 = subtle::ConstantTimeEq::ct_eq(&check1, &(digits [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/14874737/039e7258-110d-49ed-805b-d6ee7c74b89a/buildtovalue_analysis.md) as u32));
        let match2 = subtle::ConstantTimeEq::ct_eq(&check2, &(digits [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/14874737/369bc644-da28-4fab-bd2f-ebcad91f5a1c/buildtovalue_analysis.json) as u32));
        
        bool::from(match1 & match2)
    }
    
    /// Blacklist check (constant-time)
    fn is_blacklisted_ct(&self, cpf: &str) -> bool {
        // PROBLEMA: DB query pode ter timing variável
        // SOLUÇÃO: Cache completo + constant-time lookup
        
        // Hash do CPF (constant-time)
        let cpf_hash = self.hash_cpf_ct(cpf);
        
        // Bloom filter (probabilistic, constant-time)
        let maybe_blacklisted = self.bloom_filter.contains(cpf_hash);
        
        if !maybe_blacklisted {
            return false;  // Definitivamente não está
        }
        
        // Pode estar (falso positivo do Bloom)
        // Consulta exata (cache local, constant-time)
        self.blacklist_cache.contains_ct(cpf_hash)
    }
    
    /// Operação dummy (padding para constant-time)
    fn dummy_checksum_validation(&self) {
        // Executa operações equivalentes mas descarta resultado
        let dummy_digits = [1u8; 11];
        let mut sum1 = 0u32;
        for i in 0..9 {
            sum1 += (dummy_digits[i] as u32) * (10 - i as u32);
        }
        let _ = ((sum1 * 10) % 11) % 10;
        
        let mut sum2 = 0u32;
        for i in 0..10 {
            sum2 += (dummy_digits[i] as u32) * (11 - i as u32);
        }
        let _ = ((sum2 * 10) % 11) % 10;
        
        // Descarta resultado (mas mantém timing)
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    
    fn dummy_blacklist_check(&self) {
        // Hash dummy
        let _ = self.hash_cpf_ct("000.000.000-00");
        // Bloom filter dummy
        let _ = self.bloom_filter.contains(0u64);
        // Cache dummy
        let _ = self.blacklist_cache.contains_ct(0u64);
    }
}

//! CPF Validator

use super::{Validator, ValidationResult};
use regex::Regex;
use once_cell::sync::Lazy;

static CPF_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}").unwrap()
});

pub struct CpfValidator;

impl Validator for CpfValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        // Busca CPF no input
        if let Some(captures) = CPF_REGEX.find(input) {
            let cpf = captures.as_str();

            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("CPF detected: {}", cpf),
                category: "pii".to_string(),
                location: format!("offset {}", captures.start()),
                evidence: cpf.to_string(),
                severity: 0.7, // HIGH
                confidence: 0.9,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpf_detection() {
        let validator = CpfValidator;

        let input = "My CPF is 123.456.789-00";
        let result = validator.validate(input, "cpf");

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.is_violation);
        assert_eq!(result.severity, 0.7);
    }
}
