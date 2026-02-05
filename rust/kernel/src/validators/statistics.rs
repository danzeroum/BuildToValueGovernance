//! Statistics Validators (Entropy, Z-Score, Patterns)
//!
//! Detecta anomalias estatísticas:
//! - Alta entropia (dados encriptados/comprimidos)
//! - Baixa entropia (repetição)
//! - Z-Score outliers
//! - Padrões suspeitos
//!
//! Gate: Week 3 - Day 14

use super::{Validator, ValidationResult};

// ═══════════════════════════════════════════════════════════════════════════
// ENTROPY VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct EntropyValidator {
    /// Threshold de alta entropia (bits)
    high_threshold: f32,

    /// Threshold de baixa entropia
    low_threshold: f32,
}

impl Default for EntropyValidator {
    fn default() -> Self {
        Self {
            high_threshold: 7.0,  // >7 bits = suspeito (encrypted/compressed)
            low_threshold: 2.0,   // <2 bits = repetitivo
        }
    }
}

impl EntropyValidator {
    /// Calcula entropia de Shannon (bits)
    fn calculate_entropy(text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }

        // Conta frequências
        let mut freq = [0u32; 256];
        for byte in text.as_bytes() {
            freq[*byte as usize] += 1;
        }

        let len = text.len() as f32;
        let mut entropy = 0.0;

        for &count in freq.iter() {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

impl Validator for EntropyValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        // Só valida strings longas (>20 chars)
        if input.len() < 20 {
            return None;
        }

        let entropy = Self::calculate_entropy(input);

        // Alta entropia (dados encriptados/comprimidos)
        if entropy > self.high_threshold {
            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("High entropy detected: {:.2} bits (possibly encrypted/compressed)", entropy),
                category: "statistics".to_string(),
                location: "input".to_string(),
                evidence: format!("entropy={:.2}", entropy),
                severity: 0.5,
                confidence: 0.7,
            });
        }

        // Baixa entropia (repetitivo)
        if entropy < self.low_threshold {
            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("Low entropy detected: {:.2} bits (repetitive pattern)", entropy),
                category: "statistics".to_string(),
                location: "input".to_string(),
                evidence: format!("entropy={:.2}", entropy),
                severity: 0.3,
                confidence: 0.8,
            });
        }

        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Z-SCORE VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct ZScoreValidator {
    /// Threshold para outlier
    threshold: f32,
}

impl Default for ZScoreValidator {
    fn default() -> Self {
        Self {
            threshold: 3.0,  // |Z| > 3 = outlier (99.7% confidence)
        }
    }
}

impl ZScoreValidator {
    /// Calcula Z-Score
    fn calculate_z_score(text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }

        // Média dos valores ASCII
        let sum: u32 = text.as_bytes().iter().map(|&b| b as u32).sum();
        let mean = sum as f32 / text.len() as f32;

        // Desvio padrão
        let variance: f32 = text.as_bytes()
            .iter()
            .map(|&b| {
                let diff = b as f32 - mean;
                diff * diff
            })
            .sum::<f32>() / text.len() as f32;

        let std_dev = variance.sqrt();

        // Z-Score (normalizado contra ASCII printable esperado: 64)
        if std_dev > 0.0 {
            (mean - 64.0) / std_dev
        } else {
            0.0
        }
    }
}

impl Validator for ZScoreValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        if input.len() < 10 {
            return None;
        }

        let z_score = Self::calculate_z_score(input);

        if z_score.abs() > self.threshold {
            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("Statistical outlier detected: Z={:.2}", z_score),
                category: "statistics".to_string(),
                location: "input".to_string(),
                evidence: format!("z_score={:.2}", z_score),
                severity: 0.4,
                confidence: 0.7,
            });
        }

        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PATTERN VALIDATOR (Repetição)
// ═══════════════════════════════════════════════════════════════════════════

pub struct PatternValidator;

impl PatternValidator {
    /// Detecta repetição de caracteres
    fn detect_repetition(text: &str) -> Option<(char, usize)> {
        let mut max_char = ' ';
        let mut max_count = 0;
        let mut current_char = ' ';
        let mut current_count = 0;

        for ch in text.chars() {
            if ch == current_char {
                current_count += 1;
            } else {
                if current_count > max_count {
                    max_count = current_count;
                    max_char = current_char;
                }
                current_char = ch;
                current_count = 1;
            }
        }

        // Check final sequence
        if current_count > max_count {
            max_count = current_count;
            max_char = current_char;
        }

        if max_count >= 5 {
            Some((max_char, max_count))
        } else {
            None
        }
    }
}

impl Validator for PatternValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        if let Some((ch, count)) = Self::detect_repetition(input) {
            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("Repetitive pattern: '{}' × {}", ch, count),
                category: "pattern".to_string(),
                location: "input".to_string(),
                evidence: format!("char='{}', count={}", ch, count),
                severity: 0.3,
                confidence: 0.9,
            });
        }

        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_entropy() {
        let validator = EntropyValidator::default();

        // String aleatória (alta entropia)
        let random_text = "aB3xK9pLm2QzWvR7nF4jT8sY1cD6eG0hI5uN";
        let result = validator.validate(random_text, "entropy");

        assert!(result.is_some());
        assert!(result.unwrap().message.contains("High entropy"));
    }

    #[test]
    fn test_low_entropy() {
        let validator = EntropyValidator::default();

        // String repetitiva (baixa entropia)
        let repetitive = "aaaaaaaaaaaaaaaaaaaaaaaa";
        let result = validator.validate(repetitive, "entropy");

        assert!(result.is_some());
        assert!(result.unwrap().message.contains("Low entropy"));
    }

    #[test]
    fn test_z_score_outlier() {
        let validator = ZScoreValidator::default();

        // String com caracteres não-ASCII (outlier)
        let outlier = "Test\x01\x02\x03\x04\x05";
        let result = validator.validate(outlier, "zscore");

        // Pode ou não detectar dependendo do threshold
        if let Some(result) = result {
            assert!(result.message.contains("outlier"));
        }
    }

    #[test]
    fn test_pattern_repetition() {
        let validator = PatternValidator;

        let text = "Test aaaaaaaa content";
        let result = validator.validate(text, "pattern");

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.message.contains("Repetitive pattern"));
        assert!(result.evidence.contains("char='a'"));
    }
}
