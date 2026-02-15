//! Char Ratio Analyzer

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity, InputStatistics};
use crate::evidence::Finding;
use std::collections::HashSet;

pub struct CharRatioAnalyzer;

impl CharRatioAnalyzer {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, input: &str, stats: &mut InputStatistics) {
        if input.is_empty() {
            return;
        }

        let total = input.chars().count() as f32;
        let mut digits = 0;
        let mut letters = 0;
        let mut symbols = 0;
        let mut unique_chars = HashSet::new();

        for ch in input.chars() {
            unique_chars.insert(ch);
            if ch.is_numeric() {
                digits += 1;
            } else if ch.is_alphabetic() {
                letters += 1;
            } else if !ch.is_whitespace() {
                symbols += 1;
            }
        }

        stats.unique_chars = unique_chars.len() as u16;
        stats.total_chars = total as u32;
        stats.digit_ratio = digits as f32 / total;
        stats.letter_ratio = letters as f32 / total;
        stats.symbol_ratio = symbols as f32 / total;
    }

    pub fn validate(&self, stats: &InputStatistics) -> Vec<Finding> {
        let mut findings = Vec::new();

        if stats.digit_ratio > 0.8 && stats.total_chars > 20 {
            findings.push(
                Finding::new(
                    ValidatorModule::Statistics,
                    TechnicalSeverity::Low,
                    "STATISTICS_HIGH_DIGIT_RATIO",
                    "HIGH_DIGIT_RATIO",
                    &format!("High digit ratio: {:.0}%", stats.digit_ratio * 100.0),
                )
                    .with_confidence(150)
            );
        }

        if stats.unique_chars < 10 && stats.total_chars > 50 {
            findings.push(
                Finding::new(
                    ValidatorModule::Statistics,
                    TechnicalSeverity::Low,
                    "STATISTICS_LOW_DIVERSITY",
                    "LOW_CHARACTER_DIVERSITY",
                    &format!("Only {} unique characters in {} total",
                             stats.unique_chars, stats.total_chars),
                )
                    .with_confidence(120)
            );
        }

        findings
    }
}

impl Module for CharRatioAnalyzer {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
        self.analyze(input, &mut ctx.stats);
        self.validate(&ctx.stats)
    }

    fn name(&self) -> &'static str { "char_ratio" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Statistics }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.08, 0.15, 20260209, 300)
            .with_limitations("Idiomas CJK alteram proporções naturais.")
            .with_affected_groups("N/A")
    }
}