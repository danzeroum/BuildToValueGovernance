//! Prompt Injection Detector v1.1.0 (ADR-028)
//!
//! Integra Tier 0 (Universal Hardcoded) com Tier 1/2 (Pattern Registry).

mod universal; // 1. Declara o arquivo local universal.rs

use crate::security::pattern_registry::REGISTRY; // 2. Importa o REGISTRY global
use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

// Re-exporta tipos de universal para uso externo
pub use universal::{detect_tier0, Severity, ThreatCategory, ThreatSignal};

// ─────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────
#[allow(dead_code)]

const INSTRUCTION_DENSITY_THRESHOLD: f32 = 0.15;
const MIN_INPUT_LENGTH: usize = 10;

// ─────────────────────────────────────────────────────────────
// DETECTOR
// ─────────────────────────────────────────────────────────────

pub struct PromptInjectionDetector;

impl Default for PromptInjectionDetector {
    fn default() -> Self { Self::new() }
}

impl PromptInjectionDetector {
    pub fn new() -> Self { Self }

    #[allow(dead_code)]
    fn instruction_density(input: &str) -> f32 {
        let words: Vec<&str> = input.split_whitespace().collect();
        if words.is_empty() { return 0.0; }
        let keywords = ["ignore", "forget", "override", "bypass", "instructions"];
        let count = words.iter().filter(|w| keywords.iter().any(|k| w.to_lowercase().contains(k))).count();
        count as f32 / words.len() as f32
    }

    const CONTEXT_WHITELIST: &[(&str, &[&str])] = &[
        // RT-001 FP: fp-ignore-noise — "ignore the noise in the background"
        ("ignore", &["git ignore", "ignore error", "css override", "ignore the noise", "ignore noise", "ignore the background"]),
        // RT-001 FP: fp-bypass-traffic — "bypass a traffic jam"
        ("bypass", &["bypass cache", "bypass proxy", "bypass traffic", "bypass a traffic", "bypass the traffic", "bypass the queue", "bypass queue"]),
        ("override", &["method override", "config override"]),
        ("kill", &["kill process", "kill switch"]),
        // RT-001 FP: fp-system-requirements — "System requirements: 8GB RAM"
        ("system", &["operating system", "file system", "system requirements", "system specs", "system information", "system configuration"]),
        // RT-001 FP: fp-pretend-teaching — "Pretend you are helping a student"
        // (handled via is_educational_context below)
        ("pretend", &["pretend you are helping", "pretend you are teaching", "pretend you are a teacher", "pretend you are a tutor"]),
        // RT-001 FP: fp-act-as-if-medieval — "act as if this scenario happened in medieval times"
        ("act as if", &["act as if this scenario", "act as if it happened", "act as if this happened", "act as if we were", "act as if you were in"]),
    ];

    fn is_whitelisted(input: &str) -> bool {
        let lower = input.to_lowercase();
        for (trigger, safe_contexts) in Self::CONTEXT_WHITELIST {
            if lower.contains(trigger) {
                if safe_contexts.iter().any(|ctx| lower.contains(ctx)) {
                    return true;
                }
            }
        }
        false
    }
}

impl Module for PromptInjectionDetector {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
        if input.len() < MIN_INPUT_LENGTH { return Vec::new(); }
        if Self::is_whitelisted(input) { return Vec::new(); }

        let mut findings = Vec::new();

        // --- ETAPA 1: TIER 0 (Universal Hardcoded) ---
        // Executa primeiro. Se crítico, retorna imediatamente (Fail-secure).
        if let Some(signal) = detect_tier0(input) {
            let severity = match signal.severity {
                Severity::Critical => TechnicalSeverity::Critical(255),
                Severity::High => TechnicalSeverity::High,
                Severity::Medium => TechnicalSeverity::Medium,
                Severity::Low => TechnicalSeverity::Low,
            };

            // Converte ThreatCategory para &str simples para evitar erros de lifetime
            let category_str = match signal.category {
                ThreatCategory::Jailbreak => "JAILBREAK",
                ThreatCategory::RlmRecursion => "RLM_RECURSION",
                ThreatCategory::RlmCodeExec => "RLM_CODE_EXEC",
                ThreatCategory::Obfuscation => "OBFUSCATION",
            };

            findings.push(
                Finding::new(
                    ValidatorModule::PromptInjection,
                    severity,
                    signal.pattern_id,
                    category_str,
                    input,
                ).with_confidence(signal.confidence)
            );

            if signal.severity == Severity::Critical {
                return findings;
            }
        }

        // --- ETAPA 2: TIER 1/2 (Pattern Registry) ---
        let snap = REGISTRY.load();
        ctx.flags.pattern_epoch = snap.epoch;

        let (t0, t1, t2) = snap.count_by_tier(input, ctx.flags.lang_bitmask);
        let pattern_count = t0 + t1 + t2;

        if pattern_count > 0 {
            findings.push(
                Finding::new(
                    ValidatorModule::PromptInjection,
                    TechnicalSeverity::High,
                    "PATTERN_MATCH_REGISTRY",
                    "INJECTION_PATTERN",
                    input,
                ).with_confidence(80)
            );
        }

        findings
    }

    fn name(&self) -> &'static str { "prompt_injection" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::PromptInjection }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.08, 0.18, 20260220, 350)
            .with_limitations("Heuristic + Regex based. May FP on code snippets.")
            .with_affected_groups("Developers, AI Researchers.")
    }
}