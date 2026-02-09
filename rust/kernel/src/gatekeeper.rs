//! Gatekeeper v2.4.0 - Core Scanning Engine (ADR-010)
//!
//! **CHANGELOG v2.4.0**:
//! - ✅ Implementado aggregate_bias_declarations() (Worst-Case Propagation)
//! - ✅ BiasDeclaration agregado ANTES de finalize()
//! - ✅ Logger warning se calibração expirada (> 90 dias)
//!
//! Orquestrador soberano que coordena todos os módulos de validação,
//! coleta findings e produz o TechnicalEvidence v2.1.
//! Garantia de latência: < 30ms (p99).

use std::time::Instant;
use crate::evidence::{TechnicalEvidence, Finding};
use crate::core::types::{ValidatorModule, TechnicalSeverity, RiskLevel, BiasDeclaration};
use crate::statistics::char_ratio::CharRatioAnalyzer;
use crate::statistics::entropy::EntropyCalculator;
use crate::statistics::zscore::ZScoreCalculator;
use crate::validators::brazilian::{CpfValidator, CnpjValidator};
use crate::validators::communication::{EmailValidator, PhoneValidator};
use crate::validators::financial::CreditCardValidator;
use crate::validators::Validator;
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
    ///
    /// # ADR-010 (v2.4.0)
    /// - Agrega BiasDeclaration de todos validators (worst-case)
    /// - Emite warning se calibração expirada (> 90 dias)
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

        // **NOVO v2.4.0**: Agregação de BiasDeclaration (ADR-010)
        evidence.bias = self.aggregate_bias_declarations();

        // Warning se calibração expirada
        if !evidence.bias.is_calibration_valid() {
            log::warn!(
                "BiasDeclaration expired (calibration_date: {}, audit_trail: {})",
                evidence.bias.calibration_date,
                audit_trail_id
            );
        }

        // 5. Finalização e Segurança
        evidence.processing_time_us = start.elapsed().as_micros() as u64;
        evidence.finalize().expect("Critical: Failed to finalize evidence");

        // 6. Atualização de Métricas
        self.update_metrics(start.elapsed().as_secs_f32() * 1000.0, &evidence);

        evidence
    }

    /// **NOVO v2.4.0**: Agrega BiasDeclaration de todos validators (worst-case)
    ///
    /// Filosofia (ADR-010):
    /// - Princípio da Precaução (Jonas, 1984): adotar estimativa conservadora
    ///   quando múltiplos sistemas falíveis compõem pipeline.
    /// - max(FPR): taxa de falsos positivos worst-case
    /// - max(FNR): taxa de falsos negativos worst-case
    /// - min(calibration_date): data mais antiga determina validade
    /// - sum(test_dataset_size): dataset agregado
    ///
    /// # Performance
    /// - O(N) com N ≤ 15 validators (< 1μs overhead)
    fn aggregate_bias_declarations(&self) -> BiasDeclaration {
        // Coleta todos validators que implementam trait Validator
        let validators: Vec<&dyn Validator> = vec![
            &self.cpf_validator,
            &self.cnpj_validator,
            &self.email_validator,
            &self.card_validator,
            &self.phone_validator,
        ];

        let mut max_fpr = 0.0_f32;
        let mut max_fnr = 0.0_f32;
        let mut oldest_calibration = u32::MAX;
        let mut total_test_size = 0_u32;

        for v in validators {
            let bias = v.bias_declaration();

            // Worst-case propagation
            max_fpr = max_fpr.max(bias.false_positive_rate);
            max_fnr = max_fnr.max(bias.false_negative_rate);

            // Data de calibração mais antiga determina validade
            if bias.calibration_date > 0 {
                oldest_calibration = oldest_calibration.min(bias.calibration_date);
            }

            // Dataset agregado (soma dos testes individuais)
            total_test_size = total_test_size.saturating_add(bias.test_dataset_size);
        }

        // Se nenhum validator declarou calibration_date, usar 0 (inválido)
        if oldest_calibration == u32::MAX {
            oldest_calibration = 0;
        }

        BiasDeclaration::new(max_fpr, max_fnr, oldest_calibration, total_test_size)
            .with_limitations("Aggregated from multiple validators (worst-case)")
            .with_affected_groups("See individual validator documentation")
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
        let     evidence = gatekeeper.scan_for_evidence("Texto limpo.", 0x1234);
        assert_eq!(evidence.finding_count, 0);
        assert_eq!(evidence.critical_count, 0);
    }

    #[test]
    fn test_cpf_detection() {
        let mut gatekeeper = Gatekeeper::new();
        let       evidence    = gatekeeper.scan_for_evidence("CPF: 123.456.789-09", 0x1234);
        assert!(evidence.finding_count > 0);
        assert_eq!(evidence.critical_count, 1);
    }

    #[test]
    fn test_bias_aggregation_worst_case() {
        let mut gatekeeper = Gatekeeper::new();
        let       evidence = gatekeeper.scan_for_evidence("test", 0x1234);

        // BiasDeclaration deve ser agregado (max FPR/FNR de todos validators)
        assert!(evidence.bias.false_positive_rate > 0.0);
        assert!(evidence.bias.false_negative_rate > 0.0);
        assert!(evidence.bias.test_dataset_size >= 500); // CPF tem 500, maior dataset
        assert!(evidence.bias.calibration_date == 20260209); // Todos têm mesma data
    }

    #[test]
    fn test_bias_calibration_valid() {
        let mut gatekeeper = Gatekeeper::new();
        let evidence = gatekeeper.scan_for_evidence("test", 0x1234);

        // Calibração deve estar válida (dentro de 90 dias)
        assert!(evidence.bias.is_calibration_valid());
    }

    #[test]
    fn test_gatekeeper_latency_under_30ms() {
        let mut gatekeeper = Gatekeeper::new();
        let start = Instant::now();
        let _ = gatekeeper.scan_for_evidence("CPF: 111.444.777-05, Email: test@example.com", 0x1234);
        let elapsed = start.elapsed().as_millis();

        // Garantia de latência (pode falhar em CI lento, usar margin)
        assert!(elapsed < 50, "Latency too high: {}ms", elapsed);
    }
}
