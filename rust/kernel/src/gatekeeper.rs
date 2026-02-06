//! Gatekeeper v2.3.1 - Core Scanning Engine
//!
//! Orquestrador soberano que coordena todos os módulos de validação,
//! coleta findings e produz o TechnicalEvidence v2.1.
//! Garantia de latência: < 30ms (p99).

use std::time::Instant;
use crate::evidence::{TechnicalEvidence, Finding};
use crate::core::types::{ValidatorModule, TechnicalSeverity, RiskLevel};
use crate::statistics::char_ratio::CharRatioAnalyzer;
use crate::statistics::entropy::EntropyCalculator;
use crate::statistics::zscore::ZScoreCalculator;
use crate::validators::brazilian::{CpfValidator, CnpjValidator};
use crate::validators::communication::{EmailValidator, PhoneValidator};
use crate::validators::financial::CreditCardValidator;
use crate::deobfuscator::{Base64Detector, HexDecoder, LeetspeakDetector};

// ═══════════════════════════════════════════════════════════════════════════
// ESTRUTURAS DE MÉTRICAS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Default, Clone)]
pub struct GatekeeperMetrics {
    pub scans_total: u64,
    pub findings_total: u64,
    pub critical_findings: u64,
    pub avg_latency_ms: f32,
    pub p99_latency_ms: f32,
}

// ═══════════════════════════════════════════════════════════════════════════
// GATEKEEPER ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct Gatekeeper {
    // Métricas de performance
    pub metrics: GatekeeperMetrics,

    // Validators (PII & Business Rules)
    cpf_validator: CpfValidator,
    cnpj_validator: CnpjValidator,
    email_validator: EmailValidator,
    card_validator: CreditCardValidator,
    phone_validator: PhoneValidator,

    // Statistics (Anomaly Detection)
    entropy_calculator: EntropyCalculator,
    zscore_calculator: ZScoreCalculator,
    char_ratio_analyzer: CharRatioAnalyzer,

    // Deobfuscator (Evasion Prevention)
    base64_detector: Base64Detector,
    hex_decoder: HexDecoder,
    leet_detector: LeetspeakDetector,
}

impl Gatekeeper {
    /// Inicializa o Gatekeeper com todos os motores de busca
    pub fn new() -> Self {
        Self {
            metrics: GatekeeperMetrics::default(),
            cpf_validator: CpfValidator::new(),
            cnpj_validator: CnpjValidator::new(),
            email_validator: EmailValidator::new(),
            card_validator: CreditCardValidator::new(),
            phone_validator: PhoneValidator::new(),
            entropy_calculator: EntropyCalculator::new(),
            zscore_calculator: ZScoreCalculator::new(),
            char_ratio_analyzer: CharRatioAnalyzer::new(),
            base64_detector: Base64Detector::new(),
            hex_decoder: HexDecoder::new(),
            leet_detector: LeetspeakDetector::new(),
        }
    }

    /// Escaneia input e gera TechnicalEvidence completo
    ///
    /// # Performance
    /// - Target: < 30ms (p99)
    /// - Pipeline multi-estágio: Validators -> Statistics -> Deobfuscator
    pub fn scan_for_evidence(&mut self, input: &str, audit_trail_id: u128)
                             -> TechnicalEvidence
    {
        let start = Instant::now();
        let mut evidence = TechnicalEvidence::new(audit_trail_id);

        // 1. Integridade do Request Original
        let mut hasher = blake3::Hasher::new();
        hasher.update(input.as_bytes());
        evidence.original_request_hash = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
        evidence.input_size = input.len() as u32;

        // 2. Estágio: VALIDATORS (PII Detection)
        evidence.executed_modules |= 1 << 0;
        self.run_validators(input, &mut evidence);

        // 3. Estágio: STATISTICS (Anomaly Detection)
        evidence.executed_modules |= 1 << 1;
        self.run_statistics(input, &mut evidence);

        // 4. Estágio: DEOBFUSCATOR (Anti-Evasion)
        evidence.executed_modules |= 1 << 2;
        self.run_deobfuscators(input, &mut evidence);

        // 5. Finalização e Segurança
        evidence.processing_time_us = start.elapsed().as_micros() as u64;
        evidence.finalize().expect("Critical: Failed to finalize evidence");

        // 6. Atualização de Métricas
        self.update_metrics(start.elapsed().as_secs_f32() * 1000.0, &evidence);

        evidence
    }

    fn run_validators(&self, input: &str, evidence: &mut TechnicalEvidence) {
        for f in self.cpf_validator.validate(input) { evidence.add_finding(f); }
        for f in self.cnpj_validator.validate(input) { evidence.add_finding(f); }
        for f in self.email_validator.validate(input) { evidence.add_finding(f); }
        for f in self.card_validator.validate(input) { evidence.add_finding(f); }
        for f in self.phone_validator.validate(input) { evidence.add_finding(f); }
    }

    fn run_statistics(&self, input: &str, evidence: &mut TechnicalEvidence) {
        for f in self.entropy_calculator.validate(input, &mut evidence.stats) { evidence.add_finding(f); }
        for f in self.zscore_calculator.validate(input, &mut evidence.stats) { evidence.add_finding(f); }

        self.char_ratio_analyzer.analyze(input, &mut evidence.stats);
        for f in self.char_ratio_analyzer.validate(&evidence.stats) { evidence.add_finding(f); }
    }

    fn run_deobfuscators(&self, input: &str, evidence: &mut TechnicalEvidence) {
        for f in self.base64_detector.detect(input) { evidence.add_finding(f); }
        for f in self.hex_decoder.detect(input) { evidence.add_finding(f); }
        for f in self.leet_detector.detect(input) { evidence.add_finding(f); }
    }

    fn update_metrics(&mut self, latency_ms: f32, evidence: &TechnicalEvidence) {
        self.metrics.scans_total += 1;
        self.metrics.findings_total += evidence.finding_count as u64;
        self.metrics.critical_findings += evidence.critical_count as u64;

        // Média móvel exponencial para latência
        let alpha = 0.1;
        self.metrics.avg_latency_ms = (alpha * latency_ms) + ((1.0 - alpha) * self.metrics.avg_latency_ms);

        if latency_ms > self.metrics.p99_latency_ms {
            self.metrics.p99_latency_ms = latency_ms;
        }
    }

    pub fn get_metrics(&self) -> &GatekeeperMetrics {
        &self.metrics
    }
}

impl Default for Gatekeeper {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_input_no_findings() {
        let mut gatekeeper = Gatekeeper::new();
        let evidence = gatekeeper.scan_for_evidence("Texto limpo.", 0x1234);
        assert_eq!(evidence.finding_count, 0);
        assert_eq!(evidence.critical_count, 0);
    }

    #[test]
    fn test_cpf_detection() {
        let mut gatekeeper = Gatekeeper::new();
        let evidence = gatekeeper.scan_for_evidence("CPF: 123.456.789-09", 0x1234);
        assert!(evidence.finding_count > 0);
        assert_eq!(evidence.critical_count, 1);
    }
}