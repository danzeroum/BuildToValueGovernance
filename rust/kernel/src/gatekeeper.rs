//! Gatekeeper v2.6.1 — Pipeline de estágios (F1.5-05)
//!
//! Estágios ordenados:
//! 1. Deobfuscate: normaliza input (Base64, Hex, Leetspeak)
//! 2. Analyze: preenche statistics (Entropy, ZScore, CharRatio)
//! 3. Validate: detecta PII/violações (CPF, CNPJ, Email, Phone, CC)
//!    3.5. Re-scan: deobfuscator chaining + re-validate decoded text
//! 4. Finalize: bias aggregation, hash, métricas

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
// PIPELINE STAGE
// ---------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    Deobfuscate,
    Analyze,
    Validate,
}

struct StageEntry {
    module: Box<dyn Module>,
    stage: PipelineStage,
}

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
    pipeline: Vec<StageEntry>,
    metrics: GatekeeperMetrics,
}

impl Gatekeeper {
    pub fn new() -> Self {
        let pipeline = vec![
            // Stage 1: Deobfuscate
            StageEntry { module: Box::new(Base64Detector::new()), stage: PipelineStage::Deobfuscate },
            StageEntry { module: Box::new(HexDecoder::new()), stage: PipelineStage::Deobfuscate },
            StageEntry { module: Box::new(LeetspeakDetector::new()), stage: PipelineStage::Deobfuscate },
            // Stage 2: Analyze
            StageEntry { module: Box::new(EntropyCalculator::new()), stage: PipelineStage::Analyze },
            StageEntry { module: Box::new(ZScoreCalculator::new()), stage: PipelineStage::Analyze },
            StageEntry { module: Box::new(CharRatioAnalyzer::new()), stage: PipelineStage::Analyze },
            // Stage 3: Validate
            StageEntry { module: Box::new(CpfValidator::new()), stage: PipelineStage::Validate },
            StageEntry { module: Box::new(CnpjValidator::new()), stage: PipelineStage::Validate },
            StageEntry { module: Box::new(EmailValidator::new()), stage: PipelineStage::Validate },
            StageEntry { module: Box::new(CreditCardValidator::new()), stage: PipelineStage::Validate },
            StageEntry { module: Box::new(PhoneValidator::new()), stage: PipelineStage::Validate },
        ];

        Self {
            pipeline,
            metrics: GatekeeperMetrics::default(),
        }
    }

    pub fn scan_for_evidence(&mut self, input: &str, audit_trail_id: u128) -> TechnicalEvidence {
        let start = Instant::now();
        let mut evidence = TechnicalEvidence::new(audit_trail_id);

        // Input hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(input.as_bytes());
        evidence.original_request_hash = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
        evidence.input_size = input.len() as u32;

        let mut ctx = ScanContext::default();

        // Bias accumulators
        let mut max_fpr = 0.0_f32;
        let mut max_fnr = 0.0_f32;
        let mut oldest_calibration = u32::MAX;
        let mut total_test_size = 0_u32;

        // Execute pipeline stages in order
        let stage_order = [
            PipelineStage::Deobfuscate,
            PipelineStage::Analyze,
            PipelineStage::Validate,
        ];

        for &current_stage in &stage_order {
            for entry in &self.pipeline {
                if entry.stage != current_stage {
                    continue;
                }

                let findings = entry.module.scan(input, &mut ctx);
                for finding in findings {
                    evidence.add_finding(finding);
                }

                // Bitmask tracking (ADR-017)
                let bit = entry.module.module_id() as u8;
                if bit < 32 {
                    evidence.executed_modules |= 1u32 << bit;
                } else {
                    log::warn!("Module bit index overflow: {} ({})", bit, entry.module.name());
                }

                // Bias aggregation (worst-case)
                let bias = entry.module.bias_declaration();
                max_fpr = max_fpr.max(bias.false_positive_rate);
                max_fnr = max_fnr.max(bias.false_negative_rate);
                if bias.calibration_date > 0 {
                    oldest_calibration = oldest_calibration.min(bias.calibration_date);
                }
                total_test_size = total_test_size.saturating_add(bias.test_dataset_size);
            }
        }

        // Stage 3.5: Re-scan decoded content (Deobfuscator Chaining)
        let deob_chain = crate::deobfuscator::chain::DeobfuscatorChain::new();
        let chain_result = deob_chain.deobfuscate(input);
        if !chain_result.layers.is_empty() && chain_result.final_text != input {
            for entry in &self.pipeline {
                if entry.stage != PipelineStage::Validate {
                    continue;
                }
                let mut rescan_ctx = ScanContext::default();
                let findings = entry.module.scan(&chain_result.final_text, &mut rescan_ctx);
                for finding in findings {
                    evidence.add_finding(finding);
                }
            }
        }

        // Stage 4: Finalize
        evidence.stats = ctx.stats;

        evidence.bias = BiasDeclaration::new(
            max_fpr,
            max_fnr,
            if oldest_calibration == u32::MAX { 0 } else { oldest_calibration },
            total_test_size,
        )
            .with_limitations("Aggregated from all modules (worst-case)")
            .with_affected_groups("See individual module documentation");

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

    /// Number of modules registered in the pipeline.
    pub fn module_count(&self) -> usize {
        self.pipeline.len()
    }

    /// Number of modules in a specific stage.
    pub fn stage_count(&self, stage: PipelineStage) -> usize {
        self.pipeline.iter().filter(|e| e.stage == stage).count()
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