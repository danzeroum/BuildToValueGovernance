//! Core types for BuildToValue Kernel v2.3.2
//!
//! Contém Enums, Tipos primitivos e BiasDeclaration.
//! Aplicado ADR-010 (BiasDeclaration Mandate).

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------
// SERDE COMPATIBILITY (Arrays > 32)
// ---------------------------------------------------------------------
mod serde_array_compat {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(arr: &[u8; 128], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(arr)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 128], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let mut arr = [0u8; 128];
        let len = bytes.len().min(128);
        arr[..len].copy_from_slice(&bytes[..len]);
        Ok(arr)
    }

    pub mod size_256 {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(arr: &[u8; 256], serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(arr)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 256], D::Error> {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let mut arr = [0u8; 256];
            let len = bytes.len().min(256);
            arr[..len].copy_from_slice(&bytes[..len]);
            Ok(arr)
        }
    }

    pub mod size_112 {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(arr: &[u8; 112], serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(arr)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 112], D::Error> {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let mut arr = [0u8; 112];
            let len = bytes.len().min(112);
            arr[..len].copy_from_slice(&bytes[..len]);
            Ok(arr)
        }
    }
}

// ---------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------
pub const MAX_FINDINGS: usize = 10;
pub const MAX_CRITICAL_FINDINGS: usize = 3;
pub const HASH_SIZE: usize = 32;
pub const MAX_FINDING_SIZE: usize = 512;
pub const EVIDENCE_SIZE: usize = 9632;          // TechnicalEvidence (v2.1)
const MAX_CALIBRATION_DAYS: i64 = 90;

// ---------------------------------------------------------------------
// SHARED ENUMS
// ---------------------------------------------------------------------
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
    Critical(u8),   // 0-255 custom
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
        matches!(self, TechnicalSeverity::Critical(_) | TechnicalSeverity::PolicyViolation)
    }

    /// Converte para u8 (para FFI)
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Action {
    Allow = 0,
    Log = 1,
    Block = 2,
    Redact = 3,
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
    Statistics,
    // Deobfuscator
    Deobfuscator,
    // Network
    Network,
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
    PromptInjection,
}

/// Veredito ético (usado pelo Ledger)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EthicalVerdict {
    Pending = 0,
    Allow = 1,
    Educate = 2,
    Redact = 3,
    Block = 4,
}

// ---------------------------------------------------------------------
// SHARED STRUCTS
// ---------------------------------------------------------------------
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

/// Declaração de viés (ADR-010)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct BiasDeclaration {
    pub false_positive_rate: f32,
    pub false_negative_rate: f32,
    pub calibration_date: u32,               // YYYYMMDD
    pub test_dataset_size: u32,

    #[serde(with = "serde_array_compat")]
    pub affected_groups: [u8; 128],          // null-padded string

    #[serde(with = "serde_array_compat::size_256")]
    pub known_limitations: [u8; 256],        // null-padded string

    #[serde(with = "serde_array_compat::size_112")]
    pub _reserved: [u8; 112],
}

impl BiasDeclaration {
    /// Cria nova declaração com valores zerados.
    pub fn new(
        fpr: f32,
        fnr: f32,
        calibration: u32,
        dataset_size: u32,
    ) -> Self {
        Self {
            false_positive_rate: fpr,
            false_negative_rate: fnr,
            calibration_date: calibration,
            test_dataset_size: dataset_size,
            affected_groups: [0; 128],
            known_limitations: [0; 256],
            _reserved: [0; 112],
        }
    }

    /// Adiciona grupos afetados (string truncada).
    pub fn with_affected_groups(mut self, groups: &str) -> Self {
        let bytes = groups.as_bytes();
        let len = bytes.len().min(127);
        self.affected_groups[..len].copy_from_slice(&bytes[..len]);
        self.affected_groups[len] = 0; // null terminator
        self
    }

    /// Adiciona limitações conhecidas (string truncada).
    pub fn with_limitations(mut self, limitations: &str) -> Self {
        let bytes = limitations.as_bytes();
        let len = bytes.len().min(255);
        self.known_limitations[..len].copy_from_slice(&bytes[..len]);
        self.known_limitations[len] = 0;
        self
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.false_positive_rate.to_le_bytes());
        hasher.update(&self.false_negative_rate.to_le_bytes());
        hasher.update(&self.calibration_date.to_le_bytes());
        hasher.update(&self.affected_groups);

        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }

    pub fn is_calibration_valid(&self) -> bool {
        use chrono::{NaiveDate, Utc};

        if self.calibration_date == 0 {
            return false;
        }

        let year = (self.calibration_date / 10000) as i32;
        let month = (self.calibration_date / 100) % 100;
        let day = self.calibration_date % 100;

        let calibration_date = match NaiveDate::from_ymd_opt(year, month, day) {
            Some(date) => date,
            None => {
                eprintln!("Invalid calibration date: {}", self.calibration_date);
                return false;
            }
        };

        let now = Utc::now().naive_utc().date();
        let days_since = (now - calibration_date).num_days();

        if days_since < 0 {
            eprintln!("Calibration date in future: {}", calibration_date);
            return false;
        }

        days_since <= MAX_CALIBRATION_DAYS
    }
}

impl Default for BiasDeclaration {
    fn default() -> Self {
        Self::new(0.0, 0.0, 0, 0)
    }
}

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