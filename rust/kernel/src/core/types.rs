//! Core types for BuildToValue Kernel v2.3.1 (Projeto v3.0)
//!
//! Contém apenas Enums e Tipos primitivos compartilhados.
//! As estruturas complexas (Evidence, Finding) foram movidas para `crate::evidence`.
//!
//! Gate: Core Definitions - ADR-005 (Zero-Allocation)
//! **PRINCÍPIO DE JONAS**: Transparência e precisão em cálculos de calibração

use serde::{Deserialize, Serialize};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS (ADR-005: Tamanhos fixos)
// ═══════════════════════════════════════════════════════════════════════════

/// Tamanho máximo de findings normais (ring buffer)
pub const MAX_FINDINGS: usize = 10;

/// Tamanho máximo de findings críticos (sempre preservados)
pub const MAX_CRITICAL_FINDINGS: usize = 3;

/// Tamanho do hash BLAKE3 (256 bits)
pub const HASH_SIZE: usize = 32;

/// Tamanho máximo de cada finding (bytes) - ADR-005
pub const MAX_FINDING_SIZE: usize = 512;

/// Tamanho total do TechnicalEvidence (9.6KB fixos)
pub const EVIDENCE_SIZE: usize = 9600;

/// Dias máximos para calibração válida (Princípio de Jonas)
pub const MAX_CALIBRATION_DAYS: i64 = 90;

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

    pub fn to_u8(&self) -> u8 {
        match self {
            TechnicalSeverity::Info => 0,
            TechnicalSeverity::Low => 1,
            TechnicalSeverity::Medium => 2,
            TechnicalSeverity::High => 3,
            TechnicalSeverity::Critical(val) => *val,
            TechnicalSeverity::PolicyViolation => 255,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => TechnicalSeverity::Info,
            1 => TechnicalSeverity::Low,
            2 => TechnicalSeverity::Medium,
            3 => TechnicalSeverity::High,
            255 => TechnicalSeverity::PolicyViolation,
            _ => TechnicalSeverity::Critical(val),
        }
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
#[repr(u8)]
pub enum EthicalVerdict {
    Approved = 0,
    Rejected = 1,
    ManualReview = 2,
    Pending = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ValidatorModule {
    Unknown = 0,
    // Core
    CPF,
    CNPJ,
    CreditCard,
    Luhn,
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

    pub fn to_bytes(&self) -> [u8; 32] {
        unsafe {
            let mut bytes = [0u8; 32];
            let raw = std::mem::transmute::<InputStatistics, [u8; 32]>(*self);
            bytes.copy_from_slice(&raw);
            bytes
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BIAS DECLARATION (v2.3.1 - 512 bytes com cálculo preciso de datas)
// ═══════════════════════════════════════════════════════════════════════════

/// Declaração Obrigatória de Viés (Princípio de Jonas)
///
/// **ATENÇÃO**: Para garantir precisão em auditorias regulatórias, usamos
/// cálculo exato de datas via `chrono` (já dependência do projeto).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct BiasDeclaration {
    pub false_positive_rate: f32,
    pub false_negative_rate: f32,

    // Data de calibração em formato YYYYMMDD (u32)
    // Exemplo: 20240211 para 11 de fevereiro de 2024
    pub calibration_date: u32,

    pub test_dataset_size: u32,

    // Arrays fixos para strings UTF-8 (null-terminated)
    pub affected_groups: [u8; 128],
    pub known_limitations: [u8; 256],

    // Padding para garantir 512 bytes exatos (ADR-005)
    pub _reserved: [u8; 112],
}

// Garantia compile-time do tamanho fixo
static_assertions::const_assert_eq!(std::mem::size_of::<BiasDeclaration>(), 512);

impl BiasDeclaration {
    pub fn new(fpr: f32, fnr: f32, calibration_date: u32, test_size: u32) -> Self {
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

    pub fn with_affected_groups(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let len = bytes.len().min(127);
        self.affected_groups[..len].copy_from_slice(&bytes[..len]);
        self
    }

    pub fn with_limitations(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let len = bytes.len().min(255);
        self.known_limitations[..len].copy_from_slice(&bytes[..len]);
        self
    }

    /// Verifica se a calibração está válida (≤ 90 dias)
    ///
    /// Usa cálculo exato de datas via `chrono` para conformidade
    /// com o Princípio de Jonas (transparência e precisão).
    pub fn is_calibration_valid(&self) -> bool {
        use chrono::{Datelike, NaiveDate, Utc};

        // Se não há data de calibração, é inválido
        if self.calibration_date == 0 {
            return false;
        }

        // Extrai ano, mês e dia do formato YYYYMMDD
        let year = (self.calibration_date / 10000) as i32;
        let month = ((self.calibration_date / 100) % 100) as u32;
        let day = (self.calibration_date % 100) as u32;

        // Cria data de calibração
        let calibration_date = match NaiveDate::from_ymd_opt(year, month, day) {
            Some(date) => date,
            None => {
                log::error!("Invalid calibration date: {}", self.calibration_date);
                return false;
            }
        };

        // Data atual em UTC
        let now = Utc::now().naive_utc().date();

        // Calcula diferença em dias
        let days_since_calibration = match (now - calibration_date).num_days() {
            diff if diff < 0 => {
                // Data futura - inválido
                log::warn!("Calibration date is in the future: {}", calibration_date);
                return false;
            }
            diff => diff,
        };

        // Verifica se está dentro do limite (90 dias)
        days_since_calibration <= MAX_CALIBRATION_DAYS
    }

    /// Retorna dias restantes para expiração da calibração
    pub fn days_until_expiration(&self) -> i64 {
        use chrono::{Datelike, NaiveDate, Utc};

        if self.calibration_date == 0 {
            return -1; // Nunca calibrado
        }

        let year = (self.calibration_date / 10000) as i32;
        let month = ((self.calibration_date / 100) % 100) as u32;
        let day = (self.calibration_date % 100) as u32;

        let calibration_date = match NaiveDate::from_ymd_opt(year, month, day) {
            Some(date) => date,
            None => return -1,
        };

        let now = Utc::now().naive_utc().date();
        let days_since = (now - calibration_date).num_days();

        if days_since < 0 {
            -1 // Data futura
        } else {
            MAX_CALIBRATION_DAYS - days_since
        }
    }

    pub fn to_bytes(&self) -> [u8; 512] {
        unsafe { std::mem::transmute(*self) }
    }

    /// Helper para extrair string UTF-8 de array (até null terminator)
    pub fn array_to_string(arr: &[u8]) -> String {
        let end = arr.iter().position(|&b| b == 0).unwrap_or(arr.len());
        String::from_utf8_lossy(&arr[..end]).to_string()
    }
}

impl Default for BiasDeclaration {
    fn default() -> Self {
        // Data padrão: hoje (para desenvolvimento)
        let today = chrono::Utc::now().naive_utc().date();
        let calibration_date = (today.year() * 10000 + today.month() as i32 * 100 + today.day() as i32) as u32;

        Self::new(0.0, 0.0, calibration_date, 0)
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
    DataRetention,
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

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_bias_declaration_size() {
        assert_eq!(std::mem::size_of::<BiasDeclaration>(), 512);
    }

    #[test]
    fn test_bias_calibration_valid() {
        // Data de hoje deve ser válida
        let today = Utc::now().naive_utc().date();
        let today_ymd = (today.year() * 10000 + today.month() as i32 * 100 + today.day() as i32) as u32;

        let bias = BiasDeclaration::new(0.1, 0.2, today_ymd, 1000);
        assert!(bias.is_calibration_valid());
        assert!(bias.days_until_expiration() > 0);
    }

    #[test]
    fn test_bias_calibration_expired() {
        // Data há 100 dias deve estar expirada
        let hundred_days_ago = Utc::now().naive_utc().date() - Duration::days(100);
        let old_date = (hundred_days_ago.year() * 10000 + hundred_days_ago.month() as i32 * 100 + hundred_days_ago.day() as i32) as u32;

        let bias = BiasDeclaration::new(0.1, 0.2, old_date, 1000);
        assert!(!bias.is_calibration_valid());
        assert!(bias.days_until_expiration() < 0);
    }

    #[test]
    fn test_bias_calibration_future() {
        // Data futura deve ser inválida
        let future_date = 20301225; // 25/12/2030
        let bias = BiasDeclaration::new(0.1, 0.2, future_date, 1000);
        assert!(!bias.is_calibration_valid());
    }

    #[test]
    fn test_risk_level_conversion() {
        assert_eq!(RiskLevel::from_score(0.1), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_score(0.3), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.6), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(0.8), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(1.0), RiskLevel::Critical);
    }
}