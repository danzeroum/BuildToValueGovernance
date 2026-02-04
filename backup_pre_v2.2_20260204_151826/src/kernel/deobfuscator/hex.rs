
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Detecta strings hexadecimais longas (0x... ou apenas hex)
    static ref HEX_REGEX: Regex = Regex::new(
        r"(?:0x)?[0-9a-fA-F]{16,}"
    ).unwrap();
}

pub struct HexDecoder {
    rule_id: String,
}

impl HexDecoder {
    pub fn new() -> Self {
        Self {
            rule_id: "DEOBFUSCATOR_HEX_001".to_string(),
        }
    }
    
    pub fn detect(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for mat in HEX_REGEX.find_iter(input) {
            let matched = mat.as_str();
            let cleaned = matched.trim_start_matches("0x");
            
            // Tenta decodificar hex para bytes
            if let Ok(decoded) = hex::decode(cleaned) {
                // Verifica se é texto plausível
                let is_text = std::str::from_utf8(&decoded).is_ok();
                
                let finding = Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::Medium,
                    &self.rule_id,
                    "HEX_ENCODING_DETECTED",
                    &format!("Hexadecimal-encoded content detected ({})", 
                            if is_text { "text" } else { "binary" }),
                )
                .with_matched_text(matched)
                .with_position(mat.start() as u16, mat.end() as u16)
                .with_confidence(180);
                
                findings.push(finding);
            }
        }
        
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hex_detection() {
        let decoder = HexDecoder::new();
        
        // "Hello" em hex
        let findings = decoder.detect("48656c6c6f");
        assert_eq!(findings.len(), 1);
    }
    
    #[test]
    fn test_hex_with_prefix() {
        let decoder = HexDecoder::new();
        let findings = decoder.detect("0x48656c6c6f");
        assert_eq!(findings.len(), 1);
    }
}