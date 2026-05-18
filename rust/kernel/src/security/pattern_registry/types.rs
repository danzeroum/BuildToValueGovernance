//! Pattern types: CompiledPattern, PatternSnapshot, PatternMatch, PatternTier.

use regex::Regex;

/// Tier de prioridade do pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternTier {
    /// Idioma-agnóstico. Sempre executado.
    Universal,
    /// Idioma principal detectado (bit único em lang_bitmask).
    Primary,
    /// Idiomas secundários (confiança > 0.3).
    Secondary,
}

/// Pattern compilado com metadados.
#[derive(Debug)]
pub struct CompiledPattern {
    pub regex: Regex,
    pub tier: PatternTier,
    /// Bitmask dos idiomas que este pattern cobre. 0 = universal.
    pub lang_mask: u64,
    pub category: &'static str,
}

impl CompiledPattern {
    pub fn new(
        pattern: &str,
        tier: PatternTier,
        lang_mask: u64,
        category: &'static str,
    ) -> Option<Self> {
        Regex::new(pattern).ok().map(|regex| Self {
            regex,
            tier,
            lang_mask,
            category,
        })
    }

    /// Returns true if this pattern applies given the scan's lang_bitmask.
    #[inline]
    pub fn applies_to(&self, lang_bitmask: u64) -> bool {
        self.lang_mask == 0 || self.lang_mask & lang_bitmask != 0
    }
}

/// Snapshot imutável dos patterns — compartilhado via Arc.
#[derive(Debug)]
pub struct PatternSnapshot {
    pub patterns: Vec<CompiledPattern>,
    pub epoch: u64,
}

impl PatternSnapshot {
    /// Escaneia o input retornando matches (categoria, posição).
    /// Filtra por lang_bitmask — Tier 0 sempre executa.
    pub fn scan(&self, input: &str, lang_bitmask: u64) -> Vec<PatternMatch> {
        self.patterns
            .iter()
            .filter(|p| p.applies_to(lang_bitmask))
            .filter_map(|p| {
                p.regex.find(input).map(|m| PatternMatch {
                    category: p.category,
                    tier: p.tier,
                    start: m.start(),
                    end: m.end(),
                })
            })
            .collect()
    }

    /// Conta matches por tier para scoring.
    pub fn count_by_tier(&self, input: &str, lang_bitmask: u64) -> (u32, u32, u32) {
        let mut t0 = 0u32;
        let mut t1 = 0u32;
        let mut t2 = 0u32;
        for p in self.patterns.iter().filter(|p| p.applies_to(lang_bitmask)) {
            if p.regex.is_match(input) {
                match p.tier {
                    PatternTier::Universal => t0 += 1,
                    PatternTier::Primary   => t1 += 1,
                    PatternTier::Secondary => t2 += 1,
                }
            }
        }
        (t0, t1, t2)
    }
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub category: &'static str,
    pub tier: PatternTier,
    pub start: usize,
    pub end: usize,
}
