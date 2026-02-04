
use std::collections::HashMap;

/// Calculador de entropia de Shannon
/// 
/// Detecta inputs com entropia anormalmente alta ou baixa.
/// 
/// Entropia normal em português: ~4.5 bits/char
/// Entropia alta (suspeita): >6.0 bits/char (possível encoding/obfuscação)
/// Entropia baixa (suspeita): <2.0 bits/char (possível spam/repetição)
pub struct EntropyCalculator {
    rule_id_high: String,
    rule_id_low: String,
}

impl EntropyCalculator {
    pub fn new() -> Self {
        Self {
            rule_id_high: "STATISTICS_ENTROPY_HIGH".to_string(),
            rule_id_low: "STATISTICS_ENTROPY_LOW".to_string(),
        }
    }
    
    /// Calcula entropia de Shannon (bits por caractere)
    pub fn calculate(&self, input: &str) -> f32 {
        if input.is_empty() {
            return 0.0;
        }
        
        // Conta frequência de cada caractere
        let mut freq_map: HashMap<char, usize> = HashMap::new();
        for ch in input.chars() {
            *freq_map.entry(ch).or_insert(0) += 1;
        }
        
        let total = input.chars().count() as f32;
        let mut entropy = 0.0;
        
        for &count in freq_map.values() {
            let probability = count as f32 / total;
            entropy -= probability * probability.log2();
        }
        
        entropy
    }
    
    /// Valida input e retorna findings se entropia anormal
    pub fn validate(&self, input: &str, stats: &mut InputStatistics) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        let entropy = self.calculate(input);
        stats.entropy = entropy;
        
        // Entropia ALTA (suspeita de encoding)
        if entropy > 6.0 {
            let finding = Finding::new(
                ValidatorModule::Entropy,
                TechnicalSeverity::Medium,
                &self.rule_id_high,
                "HIGH_ENTROPY_DETECTED",
                &format!("Abnormally high entropy: {:.2} bits/char", entropy),
            )
            .with_confidence(Self::confidence_from_entropy(entropy, true));
            
            findings.push(finding);
        }
        
        // Entropia BAIXA (suspeita de spam/repetição)
        else if entropy < 2.0 && input.len() > 50 {
            let finding = Finding::new(
                ValidatorModule::Entropy,
                TechnicalSeverity::Low,
                &self.rule_id_low,
                "LOW_ENTROPY_DETECTED",
                &format!("Abnormally low entropy: {:.2} bits/char", entropy),
            )
            .with_confidence(Self::confidence_from_entropy(entropy, false));
            
            findings.push(finding);
        }
        
        findings
    }
    
    fn confidence_from_entropy(entropy: f32, high: bool) -> u8 {
        if high {
            // Entropia > 7.5 = 100% confiança
            // Entropia 6.0 = 50% confiança
            let normalized = ((entropy - 6.0) / 1.5).min(1.0).max(0.0);
            (128.0 + normalized * 127.0) as u8
        } else {
            // Entropia < 1.0 = 100% confiança
            // Entropia 2.0 = 50% confiança
            let normalized = ((2.0 - entropy) / 1.0).min(1.0).max(0.0);
            (128.0 + normalized * 127.0) as u8
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_normal_text_entropy() {
        let calc = EntropyCalculator::new();
        let entropy = calc.calculate("Esta é uma frase normal em português.");
        
        // Português tem entropia ~4.5 bits/char
        assert!(entropy > 3.0 && entropy < 6.0);
    }
    
    #[test]
    fn test_high_entropy_base64() {
        let calc = EntropyCalculator::new();
        let entropy = calc.calculate("U2FsdGVkX1+Qx9JYzKqJ6w8vZ3nR4mL==");
        
        // Base64 tem entropia ~6.0+ bits/char
        assert!(entropy > 6.0);
    }
    
    #[test]
    fn test_low_entropy_spam() {
        let calc = EntropyCalculator::new();
        let entropy = calc.calculate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        
        // Repetição tem entropia ~0 bits/char
        assert!(entropy < 0.5);
    }
    
    #[test]
    fn test_entropy_detection() {
        let calc = EntropyCalculator::new();
        let mut stats = InputStatistics::default();
        
        // Base64 deve gerar finding
        let findings = calc.validate("U2FsdGVkX1+Qx9JYzKqJ6w8vZ3nR4mL==", &mut stats);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, TechnicalSeverity::Medium);
    }
}