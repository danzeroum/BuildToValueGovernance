//! Gatekeeper v2.4.0 — Orquestrador soberano (ADR-017)

use crate::core::module::{Module, ScanContext};
use crate::core::types::BiasDeclaration;
use crate::evidence::TechnicalEvidence;
use std::time::Instant;

use crate::validators::brazilian::{CpfValidator, CnpjValidator};
use crate::validators::communication::{EmailValidator, PhoneValidator};
use crate::validators::financial::CreditCardValidator;
use crate::statistics::{EntropyCalculator, ZScoreCalculator, CharRatioAnalyzer};
use crate::deobfuscator::{Base64Detector, HexDecoder, LeetspeakDetector};

// ---------------------------------------------------------------------
// METRICS
// ---------------------------------------------------------------------
#[derive(Debug, Default, Clone)]
pub struct GatekeeperMetrics {
    pub scans_total: u64,
    pub findings_total: u64,
    pub critical_findings: u64,
    pub avg_latency_ms: f32,
    pub p99_latency_ms: f32,
}

// ---------------------------------------------------------------------
// GATEKEEPER
// ---------------------------------------------------------------------
pub struct Gatekeeper {
    modules: Vec<Box<dyn Module>>,
    metrics: GatekeeperMetrics,
}

impl Gatekeeper {
    pub fn new() -> Self {
        let modules: Vec<Box<dyn Module>> = vec![
            Box::new(CpfValidator::new()),
            Box::new(CnpjValidator::new()),
            Box::new(EmailValidator::new()),
            Box::new(CreditCardValidator::new()),
            Box::new(PhoneValidator::new()),
            Box::new(EntropyCalculator::new()),
            Box::new(ZScoreCalculator::new()),
            Box::new(CharRatioAnalyzer::new()),
            Box::new(Base64Detector::new()),
            Box::new(HexDecoder::new()),
            Box::new(LeetspeakDetector::new()),
        ];

        Self {
            modules,
            metrics: GatekeeperMetrics::default(),
        }
    }

    pub fn scan_for_evidence(&mut self, input: &str, audit_trail_id: u128) -> TechnicalEvidence {
        let start = Instant::now();
        let mut evidence = TechnicalEvidence::new(audit_trail_id);

        // Hash do input original
        let mut hasher = blake3::Hasher::new();
        hasher.update(input.as_bytes());
        evidence.original_request_hash = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
        evidence.input_size = input.len() as u32;

        let mut ctx = ScanContext::default();

        // Agregação de bias (pior caso)
        let mut max_fpr = 0.0_f32;
        let mut max_fnr = 0.0_f32;
        let mut oldest_calibration = u32::MAX;
        let mut total_test_size = 0_u32;

        for module in &self.modules {
            // Executa o módulo e coleta findings
            let findings = module.scan(input, &mut ctx);
            for finding in findings {
                evidence.add_finding(finding);
            }

            // Marca módulo como executado (bitmask, com proteção de overflow)
            let bit = module.module_id() as u8;
            if bit < 8 {
                evidence.executed_modules |= 1u8 << bit;
            } else {
                log::warn!("Module bit index overflow: {} ({})", bit, module.name());
            }

            // Agrega bias
            let bias = module.bias_declaration();
            max_fpr = max_fpr.max(bias.false_positive_rate);
            max_fnr = max_fnr.max(bias.false_negative_rate);
            if bias.calibration_date > 0 {
                oldest_calibration = oldest_calibration.min(bias.calibration_date);
            }
            total_test_size = total_test_size.saturating_add(bias.test_dataset_size);
        }

        // Preenche estatísticas
        evidence.stats = ctx.stats;

        // Preenche bias agregado
        evidence.bias = BiasDeclaration::new(
            max_fpr,
            max_fnr,
            if oldest_calibration == u32::MAX { 0 } else { oldest_calibration },
            total_test_size,
        )
            .with_limitations("Aggregated from all modules (worst-case)")
            .with_affected_groups("See individual module documentation");

        // Valida data de calibração (ADR-010)
        if !evidence.bias.is_calibration_valid() {
            log::warn!(
                "BiasDeclaration expired (calibration_date: {}, audit_trail: {})",
                evidence.bias.calibration_date,
                audit_trail_id
            );
        }

        evidence.processing_time_us = start.elapsed().as_micros() as u64;
        evidence.finalize().expect("Failed to finalize evidence");
        self.update_metrics(start.elapsed().as_secs_f32() * 1000.0, &evidence);

        evidence
    }

    fn update_metrics(&mut self, latency_ms: f32, evidence: &TechnicalEvidence) {
        self.metrics.scans_total += 1;
        self.metrics.findings_total += evidence.finding_count as u64;
        self.metrics.critical_findings += evidence.critical_count as u64;

        let alpha = 0.1;
        self.metrics.avg_latency_ms =
            (alpha * latency_ms) + ((1.0 - alpha) * self.metrics.avg_latency_ms);
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