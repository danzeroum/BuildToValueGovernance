//! Penalty Calculator v2.3.2
//!
//! Motor de cálculo de penalidades regulatórias baseado no framework e tipo de ameaça.
//!
//! **CHANGELOG v2.3.2**:
//! - ✅ Otimização: Remoção de PHF Map redundante (Substituído por Pure Match).
//! - ✅ Correção: Resolução do apontamento "Duplicação de Validação" do auditor.
//! - ✅ Zero-Allocation garantido (Stack only).

use crate::core::types::{ThreatType, RegulatoryFramework};

pub struct PenaltyCalculator;

impl PenaltyCalculator {
    /// Calcula a multa máxima teórica para uma infração.
    ///
    /// Retorna `Some(valor)` se houver previsão legal, ou `None` se não aplicável.
    /// Valores em moeda local da regulação (BRL para LGPD, EUR para GDPR/AI Act).
    pub fn calculate(threat: ThreatType, framework: RegulatoryFramework) -> Option<u64> {
        match (threat, framework) {
            // === LGPD (Brasil) - Art. 52 ===
            // Teto: R$ 50.000.000,00 por infração
            (ThreatType::PIILeakage, RegulatoryFramework::LGPD) => Some(50_000_000),
            // Est. Art 16 (Retenção indevida)
            (ThreatType::DenialOfWallet, RegulatoryFramework::LGPD) => Some(10_000_000),

            // === GDPR (União Europeia) - Art. 83 ===
            // Teto: € 20.000.000,00 ou 4% do faturamento
            (ThreatType::PIILeakage, RegulatoryFramework::GDPR) => Some(20_000_000),
            // Falha de segurança (Art 32)
            (ThreatType::PromptInjection, RegulatoryFramework::GDPR) => Some(10_000_000),

            // === EU AI Act (Proposta/Vigência) ===
            // Teto: € 30.000.000,00 ou 6% do faturamento (Práticas Proibidas)
            (ThreatType::ShadowAI, RegulatoryFramework::EUAIAct) => Some(30_000_000),
            // Risco alto / Discriminação
            (ThreatType::BiasViolation, RegulatoryFramework::EUAIAct) => Some(15_000_000),

            // Casos não mapeados explicitamente ou sem multa direta definida na engine
            _ => None,
        }
    }

    /// Calcula ROI (Retorno sobre Investimento) estimado de prevenção em lote.
    /// Útil para relatórios de justificação de budget de segurança.
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
    fn test_lgpd_penalties() {
        assert_eq!(
            PenaltyCalculator::calculate(ThreatType::PIILeakage, RegulatoryFramework::LGPD),
            Some(50_000_000)
        );
        // Teste de caso não mapeado (deve retornar None)
        assert_eq!(
            PenaltyCalculator::calculate(ThreatType::Toxicity, RegulatoryFramework::LGPD),
            None
        );
    }

    #[test]
    fn test_roi_batch() {
        let batch = vec![
            (ThreatType::PIILeakage, RegulatoryFramework::LGPD), // 50M
            (ThreatType::PIILeakage, RegulatoryFramework::GDPR), // 20M
            (ThreatType::Toxicity, RegulatoryFramework::LGPD),   // 0 (None)
        ];

        let total = PenaltyCalculator::calculate_roi_batch(&batch);
        assert_eq!(total, 70_000_000);
    }
}