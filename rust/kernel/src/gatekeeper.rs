//! Gatekeeper v2.7.0 — Pipeline de estágios (F1.5-05 + ADR-046)
//!
//! Estágios ordenados:
//! 1. Deobfuscate: normaliza input (Base64, Hex, Leetspeak)
//! 2. Analyze: preenche statistics (Entropy, ZScore, CharRatio)
//! 3. Validate: detecta PII/violações (CPF, CNPJ, Email, Phone, CC, LGPD Art.11)
//!    3.5. Re-scan: deobfuscator chaining + re-validate decoded text
//! 5. Finalize: bias aggregation, hash, métricas
//!
//! Wire 2 (PROP-034a): InterceptorChain com ToolScreen no pré-voo.
//! Wire 3 (P-035):     Adapter normaliza + hasha input antes do pipeline.
//! Wire 4 (PROP-031):  supply_guard::verify_skill() valida MAC + registry.

use crate::core::module::{Module, ScanContext};
use crate::core::types::BiasDeclaration;
use crate::core::adapter::{adapt, AdaptError}; // Wire 3: P-035
use crate::evidence::TechnicalEvidence;
use crate::security::supply_guard::{verify_skill, SupplyGuardResult}; // Wire 4: PROP-031

use std::time::Instant;
use crate::validators::us::SsnValidator;
use crate::validators::brazilian::{CpfValidator, CnpjValidator};
use crate::validators::communication::{EmailValidator, PhoneValidator};
use crate::validators::financial::CreditCardValidator;
use crate::validators::SensitiveDataValidator;
use crate::statistics::{EntropyCalculator, ZScoreCalculator, CharRatioAnalyzer, LanguageDetector};
use crate::deobfuscator::{Base64Detector, HexDecoder, LeetspeakDetector, Normalizer};
use crate::interceptor::{InterceptorChain, InterceptAction, ToolScreen}; // Wire 2: PROP-034a
use crate::security::prompt_injection::PromptInjectionDetector;

/// Chave MAC do kernel para PROP-031 (ADR-031b).
/// Em produção: substituir por variável de ambiente ou HSM.
/// Zero heap: &[u8] literal estático.
const KERNEL_MAC_KEY: &[u8] = b"btv-kernel-supply-guard-v1";

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
    interceptor_chain: InterceptorChain, // Wire 2: PROP-034a
}

impl Gatekeeper {
    pub fn new() -> Self {
        let pipeline = vec![
            // Stage 1: Deobfuscate
            StageEntry { module: Box::new(Normalizer::new()),        stage: PipelineStage::Deobfuscate },
            StageEntry { module: Box::new(Base64Detector::new()),    stage: PipelineStage::Deobfuscate },
            StageEntry { module: Box::new(HexDecoder::new()),        stage: PipelineStage::Deobfuscate },
            StageEntry { module: Box::new(LeetspeakDetector::new()), stage: PipelineStage::Deobfuscate },
            // Stage 2: Analyze
            StageEntry { module: Box::new(EntropyCalculator::new()),  stage: PipelineStage::Analyze },
            StageEntry { module: Box::new(ZScoreCalculator::new()),   stage: PipelineStage::Analyze },
            StageEntry { module: Box::new(CharRatioAnalyzer::new()),  stage: PipelineStage::Analyze },
            StageEntry { module: Box::new(LanguageDetector::new()),   stage: PipelineStage::Analyze },
            // Stage 3: Validate
            StageEntry { module: Box::new(CpfValidator::new()),          stage: PipelineStage::Validate },
            StageEntry { module: Box::new(CnpjValidator::new()),         stage: PipelineStage::Validate },
            StageEntry { module: Box::new(EmailValidator::new()),        stage: PipelineStage::Validate },
            StageEntry { module: Box::new(CreditCardValidator::new()),   stage: PipelineStage::Validate },
            StageEntry { module: Box::new(PhoneValidator::new()),        stage: PipelineStage::Validate },
            StageEntry { module: Box::new(PromptInjectionDetector::new()), stage: PipelineStage::Validate },
            StageEntry { module: Box::new(SsnValidator::new()),          stage: PipelineStage::Validate },
            StageEntry { module: Box::new(SensitiveDataValidator::new()), stage: PipelineStage::Validate },
        ];

        // Wire 2: PROP-034a — registra ToolScreen no InterceptorChain
        let mut interceptor_chain = InterceptorChain::new();
        interceptor_chain.add_request_hook(Box::new(ToolScreen::new()));

        // Force eager REGISTRY initialization to prevent first-scan latency spike in batch mode.
        {
            use crate::security::pattern_registry::REGISTRY;
            let _ = REGISTRY.load();
        }

        Self {
            pipeline,
            metrics: GatekeeperMetrics::default(),
            interceptor_chain,
        }
    }

    pub fn scan_for_evidence(&mut self, input: &str, audit_trail_id: u128) -> TechnicalEvidence {
        let start = Instant::now();
        let mut evidence = TechnicalEvidence::new(audit_trail_id);

        // ── Wire 3: P-035 Adapter — normalização + hash BLAKE3 canônico ──────
        let adapted = match adapt(input) {
            Ok(a) => a,
            Err(AdaptError::Empty) => {
                log::warn!("P-035 Adapter: input vazio — BLOCK audit={}", audit_trail_id);
                evidence.add_finding(crate::evidence::Finding::new(
                    crate::core::types::ValidatorModule::Unknown,
                    crate::core::types::TechnicalSeverity::Critical(255),
                    "ADAPTER_EMPTY",
                    "empty_or_whitespace_input",
                    "adapter_p035",
                ));
                evidence.processing_time_us = start.elapsed().as_micros() as u64;
                evidence.finalize().ok();
                return evidence;
            }
            Err(AdaptError::InputTooLarge { size }) => {
                log::warn!(
                    "P-035 Adapter: input oversized ({} bytes) — BLOCK audit={}",
                    size, audit_trail_id
                );
                evidence.add_finding(crate::evidence::Finding::new(
                    crate::core::types::ValidatorModule::Unknown,
                    crate::core::types::TechnicalSeverity::Critical(255),
                    "ADAPTER_INPUT_TOO_LARGE",
                    "input_exceeds_64kib",
                    "adapter_p035",
                ));
                evidence.processing_time_us = start.elapsed().as_micros() as u64;
                evidence.finalize().ok();
                return evidence;
            }
        };

        // Hash canônico: slice [0..8] de [u8; 32] é invariante estática, nunca falha.
        evidence.original_request_hash = u64::from_le_bytes(
            adapted.blake3_hash[0..8]
                .try_into()
                .unwrap_or_else(|_| panic!("BTV invariant violation: blake3_hash slice [0..8] must be exactly 8 bytes"))
        );
        evidence.input_size = adapted.normalized_len as u32;

        // ── Wire 2: PROP-034a ToolScreen — pré-voo heurístico ────────────
        let (intercept_action, _) = self.interceptor_chain.run_request(input);
        if let InterceptAction::Block(ref reason) = intercept_action {
            log::warn!(
                "PROP-034a: ToolScreen bloqueou input — reason={} audit={}",
                reason, audit_trail_id
            );
            evidence.add_finding(crate::evidence::Finding::new(
                crate::core::types::ValidatorModule::Unknown,
                crate::core::types::TechnicalSeverity::Critical(255),
                "TOOL_SCREEN_BLOCKED",
                reason,
                "tool_screen_p034a",
            ));
            evidence.processing_time_us = start.elapsed().as_micros() as u64;
            evidence.finalize().ok();
            return evidence;
        }

        // ── Wire 4 / PROP-031: Supply Guard — MAC + registry ────────────
        if evidence.has_skill_hash() {
            let hash = evidence.get_skill_hash();
            let mac_tag = evidence.get_skill_mac_tag();
            match verify_skill(hash, mac_tag, KERNEL_MAC_KEY) {
                SupplyGuardResult::Allowed => {}
                SupplyGuardResult::Blocked(ref reason) => {
                    log::warn!(
                        "PROP-031: supply_guard::verify_skill falhou — {:?} — BLOCK audit={}",
                        reason, audit_trail_id
                    );
                    evidence.add_finding(crate::evidence::Finding::new(
                        crate::core::types::ValidatorModule::Unknown,
                        crate::core::types::TechnicalSeverity::Critical(255),
                        "SKILL_PROVENANCE",
                        "supply_guard_blocked",
                        "supply_guard_p031",
                    ));
                    evidence.processing_time_us = start.elapsed().as_micros() as u64;
                    evidence.finalize().ok();
                    return evidence;
                }
            }
        }

        let mut ctx = ScanContext::default();
        ctx.flags.jurisdiction_bitmask = crate::core::module::ScanContextFlags::JURISDICTION_ALL;

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

        // Propagar stats do ctx para evidence
        evidence.stats = ctx.stats;

        // Stage 3.5a: Jurisdiction-gated PII
        {
            use crate::validators::{NhsValidator, VatValidator, IbanValidator};
            if ctx.flags.has_jurisdiction(crate::core::module::ScanContextFlags::JURISDICTION_UK) {
                let nhs = NhsValidator::new();
                for f in nhs.scan(input, &mut ctx) { evidence.add_finding(f); }
                let b = nhs.bias_declaration();
                max_fpr = max_fpr.max(b.false_positive_rate);
                max_fnr = max_fnr.max(b.false_negative_rate);
            }
            if ctx.flags.has_jurisdiction(crate::core::module::ScanContextFlags::JURISDICTION_EU) {
                let vat = VatValidator::new();
                for f in vat.scan(input, &mut ctx) { evidence.add_finding(f); }
                let b = vat.bias_declaration();
                max_fpr = max_fpr.max(b.false_positive_rate);
                max_fnr = max_fnr.max(b.false_negative_rate);

                let iban = IbanValidator::new();
                for f in iban.scan(input, &mut ctx) { evidence.add_finding(f); }
                let b = iban.bias_declaration();
                max_fpr = max_fpr.max(b.false_positive_rate);
                max_fnr = max_fnr.max(b.false_negative_rate);
            }
        }

        // Stage 3.5: Re-scan decoded content (ADR-0013-v2)
        let deob_chain = crate::deobfuscator::chain::DeobfuscatorChain::new();
        let chain_result = deob_chain.deobfuscate(input);
        if !chain_result.layers.is_empty() && chain_result.final_text != input {
            for entry in &self.pipeline {
                if entry.stage != PipelineStage::Validate { continue; }
                // ADR-0034: inherit lang_bitmask so Tier 1 language patterns apply
                // on decoded content (e.g. PT-BR injection encoded in base64).
                let mut rescan_ctx = ScanContext::default();
                rescan_ctx.flags.lang_bitmask = ctx.flags.lang_bitmask;
                rescan_ctx.flags.jurisdiction_bitmask = ctx.flags.jurisdiction_bitmask;
                let findings = entry.module.scan(&chain_result.final_text, &mut rescan_ctx);
                for finding in findings { evidence.add_finding(finding); }
            }
        }

        evidence.bias = BiasDeclaration::new(
            max_fpr, max_fnr,
            if oldest_calibration == u32::MAX { 0 } else { oldest_calibration },
            total_test_size,
        )
            .with_limitations("Aggregated from all modules (worst-case)")
            .with_affected_groups("See individual module documentation");

        if !evidence.bias.is_calibration_valid() {
            log::warn!(
                "BiasDeclaration expired (calibration_date: {}, audit_trail: {})",
                evidence.bias.calibration_date, audit_trail_id
            );
        }

        evidence.processing_time_us = start.elapsed().as_micros() as u64;
        evidence._reserved_metadata[0..8].copy_from_slice(&ctx.flags.pattern_epoch.to_le_bytes());
        evidence._reserved_metadata[8..24].copy_from_slice(&ctx.flags.tenant_key);
        // finalize() computes BLAKE3 hash and returns Ok(()); error is non-fatal for evidence.
        evidence.finalize().ok();
        self.update_metrics(start.elapsed().as_secs_f32() * 1000.0, &evidence);

        evidence
    }

    pub fn module_count(&self) -> usize { self.pipeline.len() }

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

    pub fn get_metrics(&self) -> &GatekeeperMetrics { &self.metrics }
}

impl Default for Gatekeeper {
    fn default() -> Self { Self::new() }
}
