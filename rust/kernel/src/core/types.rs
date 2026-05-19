//! Core types for BuildToValue Kernel v2.3.2
//!
//! Contém Enums, Tipos primitivos e BiasDeclaration.
//! Aplicado ADR-010 (BiasDeclaration Mandate).

use serde::{Deserialize, Serialize};
use std::fmt;
use crate::core::errors::BiasDeclarationError;

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
    SSN,
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
    ConsentRevocation,
    SensitiveData,
    InternationalTransfer,
    DataAccessRequest,
    DataErasure,
    BreachNotification,
    LanguageDetector,
    NhsNumber,
    EuVat,
    Iban,
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
    Report = 5,
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
        // repr(C, align(8)) layout: entropy(0..4), z_score(4..8), input_size(8..12),
        // digit_ratio(12..16), letter_ratio(16..20), symbol_ratio(20..24),
        // unique_chars(24..26), [pad 26..28], total_chars(28..32)
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&self.entropy.to_le_bytes());
        buf[4..8].copy_from_slice(&self.z_score.to_le_bytes());
        buf[8..12].copy_from_slice(&self.input_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.digit_ratio.to_le_bytes());
        buf[16..20].copy_from_slice(&self.letter_ratio.to_le_bytes());
        buf[20..24].copy_from_slice(&self.symbol_ratio.to_le_bytes());
        buf[24..26].copy_from_slice(&self.unique_chars.to_le_bytes());
        // bytes 26..28 are C alignment padding — stay zero
        buf[28..32].copy_from_slice(&self.total_chars.to_le_bytes());
        buf
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
    /// Validated constructor. Returns `Err` if `calibration_date == 0` or `dataset_size == 0`.
    /// Use `aggregate()` for gatekeeper aggregation where 0-values are handled explicitly.
    pub fn new(
        fpr: f32,
        fnr: f32,
        calibration: u32,
        dataset_size: u32,
    ) -> Result<Self, BiasDeclarationError> {
        if calibration == 0 {
            return Err(BiasDeclarationError::MissingCalibrationDate);
        }
        if dataset_size == 0 {
            return Err(BiasDeclarationError::MissingDatasetSize);
        }
        Ok(Self {
            false_positive_rate: fpr,
            false_negative_rate: fnr,
            calibration_date: calibration,
            test_dataset_size: dataset_size,
            affected_groups: [0; 128],
            known_limitations: [0; 256],
            _reserved: [0; 112],
        })
    }

    /// For module-level static declarations with compile-time-known valid constants.
    /// Panics at process startup if values are invalid; use `new()` for runtime values.
    #[allow(clippy::expect_used)]
    pub fn from_static(fpr: f32, fnr: f32, calibration: u32, dataset_size: u32) -> Self {
        Self::new(fpr, fnr, calibration, dataset_size)
            .expect("BiasDeclaration::from_static called with invalid compile-time constants")
    }

    /// For gatekeeper aggregation across modules. Accepts 0-values explicitly;
    /// `is_calibration_valid()` will return false and trigger a dashboard warning.
    pub fn aggregate(fpr: f32, fnr: f32, oldest_calibration: u32, total_test_size: u32) -> Self {
        Self {
            false_positive_rate: fpr,
            false_negative_rate: fnr,
            calibration_date: oldest_calibration,
            test_dataset_size: total_test_size,
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

#[cfg(test)]
impl Default for BiasDeclaration {
    fn default() -> Self {
        Self::aggregate(0.0, 0.0, 0, 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    PIILeakage,
    LanguageDetector,
    NhsNumber,
    EuVat,
    Iban,
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

// ---------------------------------------------------------------------
// ADR-061 — Decision + Negotiation Deadlock
// ---------------------------------------------------------------------

/// Unified decision emitted by the Executive pipeline (ADR-061).
///
/// `Deny` = policy rejected (calibrated risk, 24h contestation SLA).
/// `Block` = active threat, NOT a policy rejection — triggers Trust Score penalty.
/// The distinction prevents misclassifying security blocks as policy denials in the Ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Decision {
    Allow  = 0,
    Log    = 1,
    Deny   = 2,
    Block  = 3,
    Redact = 4,
    Report = 5,
}

impl Decision {
    pub fn requires_security_alert(&self) -> bool {
        matches!(self, Decision::Block)
    }

    pub fn is_contestable(&self) -> bool {
        true
    }
}

/// Fixed-size structured reason for a negotiation deadlock (ADR-061).
///
/// Produced when the negotiation engine exceeds max_rounds or SLA.
/// Recorded in the Ledger via `DeadlockResolutionError`; never produced by
/// the scanner pipeline directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NegotiationDeadlockReason {
    MaxRoundsExceeded = 0,
    TimeoutExpired    = 1,
    ConflictingPolicy = 2,
    AgentUnreachable  = 3,
}

/// Ledger-bound record of a negotiation deadlock (ADR-061).
///
/// `explanation` must be non-zero — a zeroed explanation is rejected by
/// `DeadlockResolutionError::new()`. This invariant is enforced at construction,
/// not at serialization, so a missing explanation cannot reach the Ledger.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeadlockResolutionError {
    pub reason:            NegotiationDeadlockReason,
    pub rounds_completed:  u8,
    pub agent_ids:         [u64; 2],
    #[serde(with = "serde_array_compat::size_256")]
    pub explanation:       [u8; 256],
}

impl DeadlockResolutionError {
    pub fn new(
        reason: NegotiationDeadlockReason,
        rounds_completed: u8,
        agent_ids: [u64; 2],
        explanation: &str,
    ) -> Result<Self, &'static str> {
        if explanation.is_empty() {
            return Err("explanation is required for DeadlockResolutionError");
        }
        let mut buf = [0u8; 256];
        let bytes = explanation.as_bytes();
        let len = bytes.len().min(255);
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(Self { reason, rounds_completed, agent_ids, explanation: buf })
    }
}

// ---------------------------------------------------------------------
// ADR-062 — AppealRecord (fixed-size, kernel hot-path)
// ---------------------------------------------------------------------

/// Off-chain contestation record (ADR-062). Persisted in `appeals.db`.
///
/// `blake3(explanation_text) == VerdictRecord.explanation_hash` is the
/// authenticity invariant, verified at display time by `verify_appeal_text()`.
/// Legal foundation: LGPD Art. 20.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AppealRecord {
    pub verdict_id:             [u8; 16],
    pub explanation_hash:       [u8; 32],
    pub bias_declaration_hash:  [u8; 32],
    pub timestamp_utc:          u64,
    pub appeal_deadline_utc:    u64,
    pub appeal_url_hash:        [u8; 32],
}

// ---------------------------------------------------------------------
// ADR-063 — Compile-time size invariants
// ---------------------------------------------------------------------

const _: () = assert!(
    std::mem::size_of::<BiasDeclaration>() == 512,
    "ADR-063 VIOLATION: BiasDeclaration size invariant broken (expected 512 bytes). \
     Changing field layout requires updating ADR-063 and bumping EVIDENCE_SIZE."
);

// ADR-063 phase 2: TechnicalEvidence is fully fixed-size (all Vec<u8> fields
// were replaced with [u8; N] equivalents). Enforced here and in technical.rs.
const _: () = assert!(
    std::mem::size_of::<crate::evidence::TechnicalEvidence>() == 9632,
    "ADR-063 VIOLATION: TechnicalEvidence size invariant broken (expected 9632 bytes). \
     Changing field layout requires updating EVIDENCE_SIZE and incrementing the ADR version."
);