//! Trait unificado para todos os módulos de escaneamento.
//! ScanContextFlags introduzido em ADR-032 (v1.6.0).

use crate::evidence::Finding;
use crate::core::types::{BiasDeclaration, InputStatistics, ValidatorModule};

// ─────────────────────────────────────────────────────────────────────
// SCAN CONTEXT FLAGS (ADR-032)
// ─────────────────────────────────────────────────────────────────────

/// Flags de contexto injetadas pelo gateway antes de cada scan.
///
/// Exatamente 64 bytes. Substitui `_reserved: [u8; 64]` em ScanContext.
/// INVARIANTE: zero heap. Nenhum Vec, String, Box ou Arc neste struct.
///
/// Layout (LE, align 8):
///   bytes  0- 7: lang_bitmask         — idiomas detectados (u64)
///   bytes  8-15: jurisdiction_bitmask — jurisdições habilitadas (u64)
///   bytes 16-23: capability_mask      — features ativas (u64)
///   bytes 24-39: tenant_key           — BLAKE3-128 do tenant_id ([u8;16])
///   bytes 40-47: pattern_epoch        — versão do PatternRegistry (u64)
///   bytes 48-55: lang_scores          — scores top-4 idiomas ([u16;4])
///   bytes 56-63: _reserved            — reservado v1.8+ ([u8;8])
#[derive(Debug, Default, Clone, Copy)]
#[repr(C, align(8))]
pub struct ScanContextFlags {
    pub lang_bitmask: u64,
    pub jurisdiction_bitmask: u64,
    pub capability_mask: u64,
    pub tenant_key: [u8; 16],
    pub pattern_epoch: u64,
    pub lang_scores: [u16; 4],
    pub _reserved: [u8; 8],
}

impl ScanContextFlags {
    // ── Idiomas ──────────────────────────────────────────────────
    pub const LANG_EN: u64 = 1 << 0;
    pub const LANG_PT: u64 = 1 << 1;
    pub const LANG_ES: u64 = 1 << 2;
    pub const LANG_FR: u64 = 1 << 3;
    pub const LANG_DE: u64 = 1 << 4;
    pub const LANG_RU: u64 = 1 << 5;
    pub const LANG_ZH: u64 = 1 << 6;
    pub const LANG_AR: u64 = 1 << 7;

    // ── Jurisdições ──────────────────────────────────────────────
    pub const JURISDICTION_BR: u64 = 1 << 0;
    pub const JURISDICTION_US: u64 = 1 << 1;
    pub const JURISDICTION_EU: u64 = 1 << 2;
    pub const JURISDICTION_UK: u64 = 1 << 3;
    pub const JURISDICTION_ALL: u64 = Self::JURISDICTION_BR | Self::JURISDICTION_US | Self::JURISDICTION_EU | Self::JURISDICTION_UK;

    // ── Capabilities ─────────────────────────────────────────────
    pub const CAP_PII: u64          = 1 << 0;
    pub const CAP_INJECTION: u64    = 1 << 1;
    pub const CAP_DEOBFUSC: u64     = 1 << 2;
    pub const CAP_OUTPUT: u64       = 1 << 3;
    pub const CAP_TRUSTED_ROLE: u64 = 1 << 4; // ADR-048: role-aware thresholds
    pub const CAP_ALL: u64          = u64::MAX;

    // ── Helpers ──────────────────────────────────────────────────

    #[inline]
    pub fn has_lang(&self, lang_bit: u64) -> bool {
        self.lang_bitmask & lang_bit != 0
    }

    #[inline]
    pub fn is_language_undetermined(&self) -> bool {
        self.lang_bitmask == 0
    }

    #[inline]
    pub fn has_jurisdiction(&self, j_bit: u64) -> bool {
        self.jurisdiction_bitmask & j_bit != 0
    }

    #[inline]
    pub fn has_capability(&self, cap: u64) -> bool {
        self.capability_mask & cap != 0
    }

    #[inline]
    pub fn is_default_tenant(&self) -> bool {
        self.tenant_key == [0u8; 16]
    }

    /// Retorna confiança (0.0–1.0) para o idioma no índice dado.
    /// Fixed-point: u16::MAX = 1.0.
    #[inline]
    pub fn lang_confidence(&self, index: usize) -> f32 {
        if index >= 4 {
            return 0.0;
        }
        self.lang_scores[index] as f32 / 65535.0
    }
}

// Garantia compile-time: 64 bytes exatos.
const _: () = assert!(
    core::mem::size_of::<ScanContextFlags>() == 64,
    "ScanContextFlags deve ter exatamente 64 bytes (ADR-032)"
);

// ─────────────────────────────────────────────────────────────────────
// SCAN CONTEXT
// ─────────────────────────────────────────────────────────────────────

/// Contexto compartilhado durante um scan.
/// Alocado na stack, passado por referência mutável para todos os módulos.
/// Zero heap allocations.
#[derive(Debug)]
pub struct ScanContext {
    pub stats: InputStatistics,
    /// Flags de contexto (ADR-032). Substitui `_reserved: [u8; 64]`.
    pub flags: ScanContextFlags,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            stats: InputStatistics::default(),
            flags: ScanContextFlags {
                // Single-tenant default: todas as features ativas.
                capability_mask: ScanContextFlags::CAP_ALL,
                ..Default::default()
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// MODULE TRAIT
// ─────────────────────────────────────────────────────────────────────

/// Trait unificado para todos os módulos de escaneamento.
pub trait Module: Send + Sync {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding>;
    fn name(&self) -> &'static str;
    fn module_id(&self) -> ValidatorModule;
    fn bias_declaration(&self) -> BiasDeclaration;
    /// Human-readable decision rationale for ContestabilityLoop (ADR-048).
    /// Default: empty string — legacy modules are unaffected.
    fn explain_decision(&self, _input: &str) -> &'static str { "" }
}
