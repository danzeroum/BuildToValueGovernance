use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use lazy_static::lazy_static;
use crate::evidence::Finding;
use crate::core::types::{TechnicalSeverity, ValidatorModule};

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

                // Quebra de Dependência Circular:
                // Em vez de chamar CpfValidator aqui, usamos uma heurística leve.
                // O Gatekeeper deve re-escanear o output decodificado.
                let has_suspicious_patterns = if is_text {
                    Self::heuristic_pii_check(&decoded)
                } else {
                    false
                };

                let severity = if has_suspicious_patterns {
                    TechnicalSeverity::High // Aumentamos o risco preventivamente
                } else {
                    TechnicalSeverity::Medium
                };

                let finding = Finding::new(
                    ValidatorModule::Deobfuscator,
                    severity,
                    &self.rule_id,
                    "BASE64_ENCODING_DETECTED",
                    &format!("Base64 content ({})", if is_text { "text" } else { "binary" }),
                )
                    .with_matched_text(matched)
                    .with_position(mat.start() as u16, mat.end() as u16)
                    .with_confidence(200);

                findings.push(finding);
            }
        }

        findings
    }

    /// Verificação heurística leve para evitar chamar validadores pesados aqui
    fn heuristic_pii_check(decoded: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(decoded) {
            // Procura padrões genéricos de PII (ex: XXX.XXX.XXX-XX) sem validação profunda
            text.chars().filter(|c| c.is_numeric()).count() >= 11
                && (text.contains('.') || text.contains('-'))
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
    fn test_base64_heuristic() {
        // Simula um CPF: 123.456.789-00
        let detector = Base64Detector::new();
        let encoded = general_purpose::STANDARD.encode("123.456.789-00");

        let findings = detector.detect(&encoded);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, TechnicalSeverity::High);
    }
}