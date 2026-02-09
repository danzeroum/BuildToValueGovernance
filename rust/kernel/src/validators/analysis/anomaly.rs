
use crate::evidence::finding::Finding;
use crate::core::types::{ValidatorModule, TechnicalSeverity};
use crate::validators::Validator;
use crate::statistics::{EntropyCalculator, ZScoreCalculator}; 

pub struct StatisticalValidator {
    entropy_calc: EntropyCalculator,
    zscore_calc: ZScoreCalculator,
}

impl StatisticalValidator {
    pub fn new() -> Self {
        Self {
            entropy_calc: EntropyCalculator::new(),
            zscore_calc: ZScoreCalculator::new(),
        }
    }
}

impl Validator for StatisticalValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Usa a ferramenta de Entropia
        let entropy = self.entropy_calc.calculate(input);
        
        // Aplica a regra (Policy) aqui no Validador
        if entropy > 7.0 {
            findings.push(Finding::new(
                ValidatorModule::Statistics,
                TechnicalSeverity::Medium,
                "STATISTICS_HIGH_ENTROPY",
                "HIGH_ENTROPY_DETECTED",
                &format!("Entropy level: {:.2} bits (encrypted/compressed?)", entropy)
            ));
        }

        // 2. Usa a ferramenta de Z-Score
        let zscore = self.zscore_calc.calculate(input);
        
        if zscore > 3.0 {
            findings.push(Finding::new(
                ValidatorModule::Statistics,
                TechnicalSeverity::Low,
                "STATISTICS_ABNORMAL_DIST",
                "ABNORMAL_CHAR_DISTRIBUTION",
                &format!("Z-Score: {:.2} (outlier detected)", zscore)
            ));
        }

        findings
    }

    fn name(&self) -> &'static str {
        "StatisticalValidator"
    }

    fn module(&self) -> ValidatorModule {
        ValidatorModule::Statistics
    }
}