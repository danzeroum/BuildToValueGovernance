use crate::core::types::{InputStatistics, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;
/// Analisador de proporções de tipos de caracteres
pub struct CharRatioAnalyzer;

impl CharRatioAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    /// Analisa proporções de caracteres no input
    pub fn analyze(&self, input: &str, stats: &mut InputStatistics) {
        if input.is_empty() {
            return;
        }
        
        let total = input.chars().count() as f32;
        let mut digits = 0;
        let mut letters = 0;
        let mut symbols = 0;
        let mut unique_chars = std::collections::HashSet::new();
        
        for ch in input.chars() {
            unique_chars.insert(ch);
            
            if ch.is_numeric() {
                digits += 1;
            } else if ch.is_alphabetic() {
                letters += 1;
            } else if !ch.is_whitespace() {
                symbols += 1;
            }
        }
        
        stats.unique_chars = unique_chars.len() as u16;
        stats.total_chars = total as u32;
        stats.digit_ratio = digits as f32 / total;
        stats.letter_ratio = letters as f32 / total;
        stats.symbol_ratio = symbols as f32 / total;
    }
    
    /// Valida se proporções são suspeitas
    pub fn validate(&self, stats: &InputStatistics) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Proporção de dígitos > 80% é suspeita (possível dado estruturado)
        if stats.digit_ratio > 0.8 && stats.total_chars > 20 {
            let finding = Finding::new(
                ValidatorModule::Statistics,
                TechnicalSeverity::Low,
                "STATISTICS_HIGH_DIGIT_RATIO",
                "HIGH_DIGIT_RATIO",
                &format!("High digit ratio: {:.0}%", stats.digit_ratio * 100.0),
            )
            .with_confidence(150);
            
            findings.push(finding);
        }
        
        // Muito poucos caracteres únicos (possível repetição)
        if stats.unique_chars < 10 && stats.total_chars > 50 {
            let finding = Finding::new(
                ValidatorModule::Statistics,
                TechnicalSeverity::Low,
                "STATISTICS_LOW_DIVERSITY",
                "LOW_CHARACTER_DIVERSITY",
                &format!("Only {} unique characters in {} total", 
                        stats.unique_chars, stats.total_chars),
            )
            .with_confidence(120);
            
            findings.push(finding);
        }
        
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_normal_text_ratios() {
        let analyzer = CharRatioAnalyzer::new();
        let mut stats = InputStatistics::default();
        
        analyzer.analyze("Esta é uma frase normal.", &mut stats);
        
        // Texto normal tem alta proporção de letras
        assert!(stats.letter_ratio > 0.5);
        assert!(stats.digit_ratio < 0.1);
    }
    
    #[test]
    #[test]
    fn test_high_digit_ratio() {
        let analyzer = CharRatioAnalyzer::new();
        let mut stats = InputStatistics::default();

        analyzer.analyze("123456789012345678901", &mut stats); // 21 dígitos

        assert_eq!(stats.digit_ratio, 1.0);
        let findings = analyzer.validate(&stats);
        assert_eq!(findings.len(), 1);
    }
}