//! Core types for BuildToValue Kernel v2.3.1
//!
//! Contém apenas Enums e Tipos primitivos compartilhados.
//! As estruturas complexas (Evidence, Finding) foram movidas para `crate::evidence`.
//!
//! Gate: Core Definitions

use serde::{Deserialize, Serialize};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Tamanho máximo de findings normais (ring buffer)
pub const MAX_FINDINGS: usize = 10;

/// Tamanho máximo de findings críticos (sempre preservados)
pub const MAX_CRITICAL_FINDINGS: usize = 3;

/// Tamanho do hash BLAKE3 (256 bits)
pub const HASH_SIZE: usize = 32;

/// Tamanho máximo de cada finding (bytes)
pub const MAX_FINDING_SIZE: usize = 512;

/// Tamanho total do TechnicalEvidence (9.4KB)
pub const EVIDENCE_SIZE: usize = 9600;

// ═══════════════════════════════════════════════════════════════════════════
// SHARED ENUMS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RiskLevel {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s < 0.2 => RiskLevel::Safe,
            s if s < 0.4 => RiskLevel::Low,
            s if s < 0.6 => RiskLevel::Medium,
            s if s < 0.8 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn to_score(&self) -> f32 {
        match self {
            RiskLevel::Safe => 0.0,
            RiskLevel::Low => 0.3,
            RiskLevel::Medium => 0.5,
            RiskLevel::High => 0.7,
            RiskLevel::Critical => 0.95,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Safe => write!(f, "SAFE"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TechnicalSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical(u8), // Permite valor customizado 0-255
    PolicyViolation = 255,
}

impl TechnicalSeverity {
    pub fn to_score(&self) -> f32 {
        match self {
            TechnicalSeverity::Info => 0.0,
            TechnicalSeverity::Low => 0.2,
            TechnicalSeverity::Medium => 0.5,
            TechnicalSeverity::High => 0.8,
            TechnicalSeverity::Critical(_) => 1.0,
            TechnicalSeverity::PolicyViolation => 1.0,
        }
    }

    pub fn is_critical(&self) -> bool {
        self.to_score() >= 0.8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Action {
    Allow,
    Log,
    Block,
    Redact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorModule {
    Unknown = 0,
    // Core
    CPF,
    CNPJ,
    CreditCard,
    Luhn, // Mantido para compatibilidade, se usado internamente
    Email,
    Phone,

    // Statistics
    Entropy,
    ZScore,
    Statistics, // CharRatio

    // Deobfuscator
    Deobfuscator,

    // Network
    Network, // IP, URL, Domain

    // Security
    SessionGuard,
    OutputGuard,

    // LGPD Compliance
    Consent,
    SensitiveData,
    InternationalTransfer,
    DataAccessRequest,
    DataErasure,
    BreachNotification,
}

// ═══════════════════════════════════════════════════════════════════════════
// SHARED STRUCTS (Small & Utility only)
// ═══════════════════════════════════════════════════════════════════════════

/// Estatísticas de entrada (Struct leve para compor TechnicalEvidence)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[repr(C, align(8))]
pub struct InputStatistics {
    pub entropy: f32,
    pub z_score: f32,
    pub input_size: u32,
    pub digit_ratio: f32,
    pub letter_ratio: f32,
    pub symbol_ratio: f32,
    pub unique_chars: u16,
    pub total_chars: u32,
}

impl InputStatistics {
    pub fn empty() -> Self {
        Self::default()
    }

    // Serialização para bytes (para hashing)
    pub fn to_bytes(&self) -> [u8; 32] {
        unsafe {
            // Nota: InputStatistics tem 32 bytes (4*5 + 2 + 4 + padding)
            // Ajustamos para garantir memória segura
            let mut bytes = [0u8; 32];
            let raw = std::mem::transmute::<InputStatistics, [u8; 32]>(*self);
            bytes.copy_from_slice(&raw);
            bytes
        }
    }
}

/// Declaração de Viés (Bias)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[repr(C, align(8))]
pub struct BiasDeclaration {
    pub false_positive_rate: f32,
    pub false_negative_rate: f32,
    pub _padding: [u8; 24],
}

impl BiasDeclaration {
    pub fn to_bytes(&self) -> [u8; 32] {
        unsafe { std::mem::transmute(*self) }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAT TYPES (Compliance)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    PIILeakage,
    PromptInjection,
    ShadowAI,
    DenialOfWallet,
    Toxicity,
    BiasViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegulatoryFramework {
    LGPD,
    GDPR,
    EUAIAct,
    CCPA,
    HIPAA,
    PCIDSS,
}