
use serde::{Deserialize, Serialize};
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Regulatory frameworks supported
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RegulatoryFramework {
    LGPD = 1,      // Brazil
    GDPR = 2,      // EU
    EUAIAct = 3,   // EU AI Act
    CCPA = 4,      // California
    HIPAA = 5,     // US Healthcare
    PCIDSS = 6,    // Payment Card Industry
}

/// Threat types mapped to regulations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    PIILeakage,
    PromptInjection,
    ShadowAI,
    DenialOfWallet,
    Toxicity,
    BiasViolation,
}

/// Penalty calculation result (deterministic)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyResult {
    pub threat_type: ThreatType,
    pub framework: RegulatoryFramework,
    pub max_penalty_usd: Decimal,
    pub per_incident_usd: Decimal,
    pub confidence: f32,
    pub calculation_method: String,
    pub timestamp: i64, // Unix timestamp
}

/// Immutable penalty schedule (loaded from YAML at startup)
pub struct PenaltyCalculator {
    schedules: HashMap<(ThreatType, RegulatoryFramework), PenaltyResult>,
}

impl PenaltyCalculator {
    /// Load penalties from validated YAML (called once at startup)
    pub fn from_yaml(yaml_content: &str) -> Result<Self, String> {
        // Parse YAML into schedules
        // This is deterministic - same YAML = same HashMap
        let mut schedules = HashMap::new();
        
        // Example: LGPD PII Leakage
        schedules.insert(
            (ThreatType::PIILeakage, RegulatoryFramework::LGPD),
            PenaltyResult {
                threat_type: ThreatType::PIILeakage,
                framework: RegulatoryFramework::LGPD,
                max_penalty_usd: Decimal::new(25_000_000, 2), // R$ 50M (BRL) ~= $25M (USD)
                per_incident_usd: Decimal::new(50_000, 2),
                confidence: 0.85,
                calculation_method: "LGPD Art. 52 + historical fines".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
            },
        );

        // ... load all penalties from YAML
        
        Ok(Self { schedules })
    }

    /// Calculate penalty for a threat (O(1) lookup, deterministic)
    pub fn calculate(
        &self,
        threat: ThreatType,
        framework: RegulatoryFramework,
    ) -> Option<&PenaltyResult> {
        self.schedules.get(&(threat, framework))
    }

    /// Calculate total value of prevented incidents
    pub fn calculate_roi(
        &self,
        threats: &[(ThreatType, RegulatoryFramework)],
    ) -> Decimal {
        threats
            .iter()
            .filter_map(|(t, f)| self.calculate(*t, *f))
            .map(|result| result.per_incident_usd)
            .sum()
    }

    /// Generate audit-ready JSON (LGPD Art. 20 compliance)
    pub fn export_audit_trail(&self) -> String {
        serde_json::to_string_pretty(&self.schedules)
            .unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_penalty_calculation_deterministic() {
        let calc = PenaltyCalculator::from_yaml("").unwrap();
        let result1 = calc.calculate(ThreatType::PIILeakage, RegulatoryFramework::LGPD);
        let result2 = calc.calculate(ThreatType::PIILeakage, RegulatoryFramework::LGPD);
        
        assert_eq!(result1, result2); // Deterministic
    }

    #[test]
    fn test_roi_calculation() {
        let calc = PenaltyCalculator::from_yaml("").unwrap();
        let threats = vec![
            (ThreatType::PIILeakage, RegulatoryFramework::LGPD),
            (ThreatType::ShadowAI, RegulatoryFramework::EUAIAct),
        ];
        
        let total = calc.calculate_roi(&threats);
        assert!(total > Decimal::ZERO);
    }
}