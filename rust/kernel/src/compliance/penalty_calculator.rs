//! Penalty Calculator v2.3.1 (OFICIAL)
//!
//! **CHANGELOG v2.3.1**:
//! - ✅ Correção de chaves PHF (Uso de string concatenada ou nested maps)
//! - ✅ Zero-Allocation REAL (Remoção do format!)
//! - ✅ ADR-001 compliance (deterministic memory)

use phf::phf_map;
use crate::core::types::{ThreatType, RegulatoryFramework};

/// Tabela de penalidades (compile-time, zero heap).
/// Para contornar a limitação de tuplas no PHF, usamos chaves concatenadas "Threat:Framework".
static PENALTY_TABLE: phf::Map<&'static str, u64> = phf_map! {
    "PIILeakage:LGPD" => 50_000_000,       // R$ 50M (Art. 52, II)
    "PIILeakage:GDPR" => 20_000_000,       // €20M (Art. 83)
    "ShadowAI:EUAIAct" => 30_000_000,      // €30M (Art. 71)
    "PromptInjection:GDPR" => 10_000_000,  // €10M (moderado)
    "DataRetention:LGPD" => 10_000_000,    // R$ 10M (Art. 16)
};

/// Penalty Calculator (Zero-Allocation)
pub struct PenaltyCalculator;

impl PenaltyCalculator {
    /// Calcula penalidade (lookup constant-time).
    ///
    /// # Performance
    /// - Lookup: O(1) via perfect hash function
    /// - Real Zero heap allocations (no Strings)
    pub fn calculate(
        threat: ThreatType,
        framework: RegulatoryFramework,
    ) -> Option<u64> {
        // ✅ CORREÇÃO: Em vez de format!, usamos match para obter a string estática.
        // Isso garante que não haja alocação de memória no hot-path.
        let key = match (threat, framework) {
            (ThreatType::PIILeakage, RegulatoryFramework::LGPD) => "PIILeakage:LGPD",
            (ThreatType::PIILeakage, RegulatoryFramework::GDPR) => "PIILeakage:GDPR",
            (ThreatType::ShadowAI, RegulatoryFramework::EUAIAct) => "ShadowAI:EUAIAct",
            (ThreatType::PromptInjection, RegulatoryFramework::GDPR) => "PromptInjection:GDPR",
            (ThreatType::DataRetention, RegulatoryFramework::LGPD) => "DataRetention:LGPD",
            _ => return None,
        };

        PENALTY_TABLE.get(key).copied()
    }

    /// Calcula ROI (batch).
    pub fn calculate_roi_batch(threats: &[(ThreatType, RegulatoryFramework)]) -> u64 {
        threats
            .iter()
            .filter_map(|(t, f)| Self::calculate(*t, *f))
            .sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_allocation_lookup() {
        let result = PenaltyCalculator::calculate(
            ThreatType::PIILeakage,
            RegulatoryFramework::LGPD,
        );

        assert_eq!(result, Some(50_000_000));
    }

    #[test]
    fn test_batch_roi_calculation() {
        let threats = vec![
            (ThreatType::PIILeakage, RegulatoryFramework::LGPD),
            (ThreatType::ShadowAI, RegulatoryFramework::EUAIAct),
        ];

        let total = PenaltyCalculator::calculate_roi_batch(&threats);
        assert_eq!(total, 80_000_000);
    }
}