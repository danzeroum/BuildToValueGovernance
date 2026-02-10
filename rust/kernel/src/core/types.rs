//! Core types for BuildToValue Kernel v2.4.0
//!
//! Contém apenas Enums e Tipos primitivos compartilhados.
//! As estruturas complexas (Evidence, Finding) foram movidas para `crate::evidence`.
//!
//! Gate: Core Definitions
//!
//! **CHANGELOG v2.4.0 (ADR-010)**:
//! - ✅ BiasDeclaration expandida de 32 para 512 bytes
//! - ✅ Adicionados campos calibration_date, test_dataset_size, affected_groups, known_limitations
//! - ✅ Validação de expiração de calibração (90 dias)

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

/// Declaração Obrigatória de Viés (Princípio de Jonas)
///
/// Documentação técnica das limitações conhecidas de cada validator,
/// com taxas de erro calibradas empiricamente e data de validade.
///
/// Filosofia: Humildade Algorítmica — reconhecer limitações é
/// pré-condição para confiança legítima (Jonas, 1984).
///
/// **v2.4.0 BREAKING CHANGE**: Expandido de 32 para 512 bytes
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct BiasDeclaration {
    /// Taxa de falsos positivos (0.0-1.0)
    pub false_positive_rate: f32,

    /// Taxa de falsos negativos (0.0-1.0)
    pub false_negative_rate: f32,

    /// Data de calibração (formato YYYYMMDD, ex: 20260209)
    /// Validade: 90 dias. Após isso, validator DEVE recalibrar.
    pub calibration_date: u32,

    /// Tamanho do dataset de teste usado para calibração
    pub test_dataset_size: u32,

    /// Grupos populacionais afetados desproporcionalmente
    /// (codificação UTF-8, max 128 bytes, null-terminated)
    /// Ex: "Brazilian Portuguese, non-standard formatting"
    pub affected_groups: [u8; 128],

    /// Limitações técnicas conhecidas (UTF-8, max 256 bytes)
    /// Ex: "Cannot detect implicit consent; 365-day validity arbitrary"
    pub known_limitations: [u8; 256],

    /// Reservado para extensão futura
    pub _reserved: [u8; 112],
}

// Garantia compile-time: 4 + 4 + 4 + 4 + 128 + 256 + 112 = 512 bytes
static_assertions::const_assert_eq!(
    std::mem::size_of::<BiasDeclaration>(),
    512
);

impl BiasDeclaration {
    /// Cria declaração com valores obrigatórios
    pub fn new(
        fpr: f32,
        fnr: f32,
        calibration_date: u32,
        test_size: u32,
    ) -> Self {
        Self {
            false_positive_rate: fpr,
            false_negative_rate: fnr,
            calibration_date,
            test_dataset_size: test_size,
            affected_groups: [0; 128],
            known_limitations: [0; 256],
            _reserved: [0; 112],
        }
    }

    /// Define grupos afetados (UTF-8 text, truncado se > 127 bytes)
    pub fn with_affected_groups(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let len = bytes.len().min(127); // Reserve 1 byte para null terminator
        self.affected_groups[..len].copy_from_slice(&bytes[..len]);
        self.affected_groups[len] = 0; // Null terminator
        self
    }

    /// Define limitações (UTF-8 text, truncado se > 255 bytes)
    pub fn with_limitations(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let len = bytes.len().min(255);
        self.known_limitations[..len].copy_from_slice(&bytes[..len]);
        self.known_limitations[len] = 0;
        self
    }

    /// Valida se calibração está dentro de 90 dias
    ///
    /// Implementação aproximada (ignora meses de 28-31 dias).
    /// Filosofia: Calibrações expiram para forçar reavaliação contínua,
    /// evitando "esquecimento institucional" de data drift.
    pub fn is_calibration_valid(&self) -> bool {
        // Parse current date as YYYYMMDD
        let now = chrono::Utc::now();
        let now_yyyymmdd = now.year() as u32 * 10000
            + now.month() * 100
            + now.day();

        if self.calibration_date == 0 || self.calibration_date > now_yyyymmdd {
            return false; // Invalid date
        }

        // Cálculo aproximado (cada mês = 30 dias)
        let cal_year = self.calibration_date / 10000;
        let cal_month = (self.calibration_date / 100) % 100;
        let cal_day = self.calibration_date % 100;

        let now_year = now_yyyymmdd / 10000;
        let now_month = (now_yyyymmdd / 100) % 100;
        let now_day = now_yyyymmdd % 100;

        let days_diff = ((now_year - cal_year) * 365) as i32
            + ((now_month as i32 - cal_month as i32) * 30)
            + (now_day as i32 - cal_day as i32);

        days_diff >= 0 && days_diff <= 90
    }

    pub fn to_bytes(&self) -> [u8; 512] {
        unsafe { std::mem::transmute(*self) }
    }
}

impl Default for BiasDeclaration {
    fn default() -> Self {
        Self::new(0.0, 0.0, 0, 0)
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