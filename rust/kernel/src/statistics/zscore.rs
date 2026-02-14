use crate::core::types::{InputStatistics, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;
use std::collections::HashMap;

/// Calculador de Z-Score (desvio padrão da distribuição de caracteres)
/// 
/// Detecta distribuições anômalas de caracteres.
/// 
/// Z-Score normal: -2.0 a +2.0
/// Z-Score alto: >3.0 (distribuição muito irregular)
pub struct ZScoreCalculator {
    rule_id: String,
}

impl ZScoreCalculator {
    pub fn new() -> Self {
        Self {
            rule_id: "STATISTICS_ZSCORE_001".to_string(),
        }
    }
    
    /// Calcula Z-Score da distribuição de caracteres
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
        let frequencies: Vec<f32> = freq_map.values()
            .map(|&count| count as f32 / total)
            .collect();
        
        // Calcula média
        let mean = frequencies.iter().sum::<f32>() / frequencies.len() as f32;
        
        // Calcula desvio padrão
        let variance = frequencies.iter()
            .map(|&f| (f - mean).powi(2))
            .sum::<f32>() / frequencies.len() as f32;
        let std_dev = variance.sqrt();
        
        // Calcula Z-Score do maior desvio
        let max_freq = frequencies.iter()
            .copied()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);
        
        if std_dev == 0.0 {
            return 0.0;
        }
        
        (max_freq - mean) / std_dev
    }
    
    /// Valida input e retorna findings se Z-Score anormal
    pub fn validate(&self, input: &str, stats: &mut InputStatistics) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        let zscore = self.calculate(input);
        stats.z_score = zscore;
        
        // Z-Score > 3.0 indica distribuição muito irregular
        if zscore > 3.0 {
            let finding = Finding::new(
                ValidatorModule::ZScore,
                TechnicalSeverity::Low,
                &self.rule_id,
                "ABNORMAL_CHAR_DISTRIBUTION",
                &format!("Z-Score: {:.2} (expected: -2.0 to +2.0)", zscore),
            )
            .with_confidence(Self::confidence_from_zscore(zscore));
            
            findings.push(finding);
        }
        
        findings
    }
    
    fn confidence_from_zscore(zscore: f32) -> u8 {
        // Z-Score > 5.0 = 100% confiança
        // Z-Score 3.0 = 50% confiança
        let normalized = ((zscore - 3.0) / 2.0).min(1.0).max(0.0);
        (128.0 + normalized * 127.0) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_normal_text_zscore() {
        let calc = ZScoreCalculator::new();
        let zscore = calc.calculate("Esta é uma frase normal.");
        
        // Distribuição normal tem Z-Score baixo
        assert!(zscore < 3.0);
    }
    
    #[test]
    fn test_abnormal_distribution() {
        let calc = ZScoreCalculator::new();
        let zscore = calc.calculate(&"a".repeat(1000));
        assert!(zscore > 3.0, "zscore = {}", zscore);
    }
}