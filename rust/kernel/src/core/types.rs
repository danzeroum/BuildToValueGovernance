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
//! - ✅ Serialize/Deserialize manual para arrays grandes
//! - ✅ EthicalVerdict adicionado (v2.3.2 Fix)

use serde::{Deserialize, Serialize};
use std::fmt;
use chrono::Datelike;

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

// ✅ CORREÇÃO CRÍTICA: Adicionando EthicalVerdict que faltava
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EthicalVerdict {
    Approved = 0,
    Rejected = 1,
    ManualReview = 2,
    Pending = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
// BIAS DECLARATION (v2.4.0 - 512 bytes)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
#[repr(C, align(8))]
pub struct BiasDeclaration {
    pub false_positive_rate: f32,
    pub false_negative_rate: f32,
    pub calibration_date: u32,
    pub test_dataset_size: u32,
    pub affected_groups: [u8; 128],
    pub known_limitations: [u8; 256],
    pub _reserved: [u8; 112],
}

// Garantia compile-time
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
        self.affected_groups[len] = 0;
        self
    }

    pub fn with_limitations(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let len = bytes.len().min(255);
        self.known_limitations[..len].copy_from_slice(&bytes[..len]);
        self.known_limitations[len] = 0;
        self
    }

    pub fn is_calibration_valid(&self) -> bool {
        let now = chrono::Utc::now();
        let now_yyyymmdd =
            now.year() as u32 * 10000 + now.month() * 100 + now.day();

        if self.calibration_date == 0 || self.calibration_date > now_yyyymmdd {
            return false;
        }

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

    fn array_to_string(arr: &[u8]) -> String {
        let end = arr.iter().position(|&b| b == 0).unwrap_or(arr.len());
        String::from_utf8_lossy(&arr[..end]).to_string()
    }
}

impl Default for BiasDeclaration {
    fn default() -> Self {
        Self::new(0.0, 0.0, 0, 0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MANUAL SERIALIZE/DESERIALIZE (Arrays grandes)
// ═══════════════════════════════════════════════════════════════════════════

impl Serialize for BiasDeclaration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BiasDeclaration", 6)?;

        state.serialize_field("false_positive_rate", &self.false_positive_rate)?;
        state.serialize_field("false_negative_rate", &self.false_negative_rate)?;
        state.serialize_field("calibration_date", &self.calibration_date)?;
        state.serialize_field("test_dataset_size", &self.test_dataset_size)?;

        state.serialize_field(
            "affected_groups",
            &Self::array_to_string(&self.affected_groups),
        )?;
        state.serialize_field(
            "known_limitations",
            &Self::array_to_string(&self.known_limitations),
        )?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for BiasDeclaration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            FalsePositiveRate,
            FalseNegativeRate,
            CalibrationDate,
            TestDatasetSize,
            AffectedGroups,
            KnownLimitations,
        }

        struct BiasVisitor;

        impl<'de> Visitor<'de> for BiasVisitor {
            type Value = BiasDeclaration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct BiasDeclaration")
            }

            fn visit_map<V>(self, mut map: V) -> Result<BiasDeclaration, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut fpr = None;
                let mut fnr = None;
                let mut date = None;
                let mut size = None;
                let mut groups: Option<String> = None;
                let mut limits: Option<String> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::FalsePositiveRate => {
                            if fpr.is_some() {
                                return Err(de::Error::duplicate_field("false_positive_rate"));
                            }
                            fpr = Some(map.next_value()?);
                        }
                        Field::FalseNegativeRate => {
                            if fnr.is_some() {
                                return Err(de::Error::duplicate_field("false_negative_rate"));
                            }
                            fnr = Some(map.next_value()?);
                        }
                        Field::CalibrationDate => {
                            if date.is_some() {
                                return Err(de::Error::duplicate_field("calibration_date"));
                            }
                            date = Some(map.next_value()?);
                        }
                        Field::TestDatasetSize => {
                            if size.is_some() {
                                return Err(de::Error::duplicate_field("test_dataset_size"));
                            }
                            size = Some(map.next_value()?);
                        }
                        Field::AffectedGroups => {
                            if groups.is_some() {
                                return Err(de::Error::duplicate_field("affected_groups"));
                            }
                            groups = Some(map.next_value()?);
                        }
                        Field::KnownLimitations => {
                            if limits.is_some() {
                                return Err(de::Error::duplicate_field("known_limitations"));
                            }
                            limits = Some(map.next_value()?);
                        }
                    }
                }

                let fpr = fpr.ok_or_else(|| de::Error::missing_field("false_positive_rate"))?;
                let fnr = fnr.ok_or_else(|| de::Error::missing_field("false_negative_rate"))?;
                let date = date.ok_or_else(|| de::Error::missing_field("calibration_date"))?;
                let size = size.ok_or_else(|| de::Error::missing_field("test_dataset_size"))?;

                let mut bias = BiasDeclaration::new(fpr, fnr, date, size);

                if let Some(g) = groups {
                    bias = bias.with_affected_groups(&g);
                }

                if let Some(l) = limits {
                    bias = bias.with_limitations(&l);
                }

                Ok(bias)
            }
        }

        const FIELDS: &[&str] = &[
            "false_positive_rate",
            "false_negative_rate",
            "calibration_date",
            "test_dataset_size",
            "affected_groups",
            "known_limitations",
        ];

        deserializer.deserialize_struct("BiasDeclaration", FIELDS, BiasVisitor)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bias_declaration_size() {
        assert_eq!(std::mem::size_of::<BiasDeclaration>(), 512);
    }
}