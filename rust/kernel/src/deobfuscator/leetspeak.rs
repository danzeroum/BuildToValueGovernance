
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    static ref LEET_MAP: HashMap<char, char> = {
        let mut m = HashMap::new();
        m.insert('0', 'o');
        m.insert('1', 'i');
        m.insert('3', 'e');
        m.insert('4', 'a');
        m.insert('5', 's');
        m.insert('7', 't');
        m.insert('8', 'b');
        m.insert('9', 'g');
        m.insert('@', 'a');
        m.insert('$', 's');
        m
    };
}

pub struct LeetspeakDetector {
    rule_id: String,
}

impl LeetspeakDetector {
    pub fn new() -> Self {
        Self {
            rule_id: "DEOBFUSCATOR_LEET_001".to_string(),
        }
    }
    
    /// Converte leetspeak para texto normal
    pub fn decode(&self, input: &str) -> String {
        input.chars()
            .map(|c| LEET_MAP.get(&c).copied().unwrap_or(c))
            .collect()
    }
    
    /// Detecta se input contém leetspeak significativo
    pub fn detect(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Conta substituições leetspeak
        let leet_count = input.chars()
            .filter(|c| LEET_MAP.contains_key(c))
            .count();
        
        let total_chars = input.chars().count();
        
        if total_chars == 0 {
            return findings;
        }
        
        let leet_ratio = leet_count as f32 / total_chars as f32;
        
        // Se > 30% dos caracteres são leetspeak, é suspeito
        if leet_ratio > 0.3 && leet_count > 5 {
            let decoded = self.decode(input);
            
            let finding = Finding::new(
                ValidatorModule::Deobfuscator,
                TechnicalSeverity::Medium,
                &self.rule_id,
                "LEETSPEAK_DETECTED",
                &format!("Leetspeak encoding detected ({:.0}% substitutions)", 
                        leet_ratio * 100.0),
            )
            .with_matched_text(&decoded)
            .with_confidence((leet_ratio * 255.0) as u8);
            
            findings.push(finding);
        }
        
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_leetspeak_decode() {
        let detector = LeetspeakDetector::new();
        assert_eq!(detector.decode("h3ll0 w0rld"), "hello world");
    }
    
    #[test]
    fn test_leetspeak_detection() {
        let detector = LeetspeakDetector::new();
        let findings = detector.detect("my p@$$w0rd 1$ $3cr3t");
        assert_eq!(findings.len(), 1);
    }
}