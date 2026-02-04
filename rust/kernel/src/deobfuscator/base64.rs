
use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Detecta strings que parecem Base64 (múltiplo de 4, caracteres válidos)
    static ref BASE64_REGEX: Regex = Regex::new(
        r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    ).unwrap();
}

pub struct Base64Detector {
    rule_id: String,
}

impl Base64Detector {
    pub fn new() -> Self {
        Self {
            rule_id: "DEOBFUSCATOR_BASE64_001".to_string(),
        }
    }
    
    pub fn detect(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for mat in BASE64_REGEX.find_iter(input) {
            let matched = mat.as_str();
            
            // Filtros para reduzir falsos positivos
            if matched.len() < 16 {
                continue;  // Muito curto para ser significativo
            }
            
            // Tenta decodificar
            if let Ok(decoded) = general_purpose::STANDARD.decode(matched) {
                // Valida se conteúdo decodificado é plausível (UTF-8 ou binário)
                let is_text = std::str::from_utf8(&decoded).is_ok();
                let has_pii = if is_text {
                    Self::check_decoded_for_pii(&decoded)
                } else {
                    false
                };
                
                let severity = if has_pii {
                    TechnicalSeverity::PolicyViolation
                } else {
                    TechnicalSeverity::Medium
                };
                
                let finding = Finding::new(
                    ValidatorModule::Deobfuscator,
                    severity,
                    &self.rule_id,
                    "BASE64_ENCODING_DETECTED",
                    &format!("Base64-encoded content detected ({})", 
                            if is_text { "text" } else { "binary" }),
                )
                .with_matched_text(matched)
                .with_position(mat.start() as u16, mat.end() as u16)
                .with_confidence(200);
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Verifica se conteúdo decodificado contém PII
    fn check_decoded_for_pii(decoded: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(decoded) {
            // Usa validadores existentes no texto decodificado
            let cpf_validator = super::super::validators::cpf::CpfValidator::new();
            !cpf_validator.validate(text).is_empty()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_base64_detection() {
        let detector = Base64Detector::new();
        
        // "Hello World" em Base64
        let findings = detector.detect("SGVsbG8gV29ybGQ=");
        assert_eq!(findings.len(), 1);
    }
    
    #[test]
    fn test_base64_with_pii() {
        let detector = Base64Detector::new();
        
        // CPF em Base64
        let cpf_encoded = general_purpose::STANDARD.encode("123.456.789-09");
        let findings = detector.detect(&cpf_encoded);
        
        // Deve detectar E aumentar severidade
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, TechnicalSeverity::PolicyViolation);
    }
}