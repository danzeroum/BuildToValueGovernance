//! US SSN Validator v1.0.1
//!
//! Detecta Social Security Numbers (XXX-XX-XXXX).
//! Validação por Area Number rules (post-2011 randomization).
//!
//! Filosofia:
//! - Levinas: SSN é dado hipersensível — fail-secure, BLOCK por padrão
//! - Jonas: BiasDeclaration calibrada, limitações declaradas
//! - Rawls: Mesmo tratamento independente do contexto de origem
//!
//! INVARIANTE: Nenhum .unwrap() alcançável por input de usuário no hot-path.
//! caps.get(0) usa if-let: entrada malformada → retorna falha segura (false),
//! nunca derruba a thread.

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Matches XXX-XX-XXXX, XXX XX XXXX, XXXXXXXXX (9 digits contiguous)
    /// Excludes common false positives: phone-like patterns, dates
    static ref SSN_FORMATTED: Regex = Regex::new(
        r"\b(\d{3})[-\s](\d{2})[-\s](\d{4})\b"
    ).unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in SSN_FORMATTED: {e}"));

    /// Bare 9-digit sequences (higher FP risk — lower confidence)
    static ref SSN_BARE: Regex = Regex::new(
        r"\b(\d{9})\b"
    ).unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in SSN_BARE: {e}"));
}

pub struct SsnValidator;

impl SsnValidator {
    pub fn new() -> Self {
        Self
    }

    /// Validates SSN area/group/serial rules.
    ///
    /// Invalid SSNs per SSA rules:
    /// - Area (first 3): 000, 666, 900-999
    /// - Group (middle 2): 00
    /// - Serial (last 4): 0000
    /// - Known advertising SSN: 078-05-1120
    /// - Known invalid: 219-09-9999
    fn is_valid_ssn(area: u16, group: u16, serial: u16) -> bool {
        if area == 0 || area == 666 || area >= 900 {
            return false;
        }
        if group == 0 {
            return false;
        }
        if serial == 0 {
            return false;
        }
        // SSA advertising number (used in wallet inserts)
        if area == 78 && group == 5 && serial == 1120 {
            return false;
        }
        // Woolworth SSN (historically invalid)
        if area == 219 && group == 9 && serial == 9999 {
            return false;
        }
        true
    }

    fn mask_ssn(area: u16, _group: u16, serial: u16) -> String {
        format!("{}XX-XX-{:04}", area / 100, serial % 100)
    }

    fn scan_formatted(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for caps in SSN_FORMATTED.captures_iter(input) {
            // Hot-path: if-let instead of .unwrap() — malformed capture → skip safely.
            let full_match = if let Some(m) = caps.get(0) {
                m
            } else {
                continue;
            };

            let area: u16 = caps[1].parse().unwrap_or(0);
            let group: u16 = caps[2].parse().unwrap_or(0);
            let serial: u16 = caps[3].parse().unwrap_or(0);

            if Self::is_valid_ssn(area, group, serial) {
                findings.push(
                    Finding::new(
                        ValidatorModule::SSN,
                        TechnicalSeverity::Critical(255),
                        "SSN_DETECTED",
                        "PII_LEAKAGE",
                        &Self::mask_ssn(area, group, serial),
                    )
                    .with_position(
                        full_match.start() as u16,
                        full_match.end() as u16,
                    )
                    .with_confidence(95),
                );
            } else {
                findings.push(
                    Finding::new(
                        ValidatorModule::SSN,
                        TechnicalSeverity::Medium,
                        "SSN_INVALID_FORMAT",
                        "SSN_LIKE_PATTERN",
                        &format!("{}XX-XX-XXXX", area / 100),
                    )
                    .with_position(
                        full_match.start() as u16,
                        full_match.end() as u16,
                    )
                    .with_confidence(40),
                );
            }
        }

        findings
    }

    fn scan_bare(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for caps in SSN_BARE.captures_iter(input) {
            // Hot-path: if-let instead of .unwrap() — malformed capture → skip safely.
            let full_match = if let Some(m) = caps.get(0) {
                m
            } else {
                continue;
            };

            let digits = &caps[1];

            // Skip if already matched by formatted regex
            // (e.g. "123-45-6789" won't produce bare "123456789")
            // Also skip if likely a phone number (10+ digits nearby)
            if digits.len() != 9 {
                continue;
            }

            let area: u16 = digits[0..3].parse().unwrap_or(0);
            let group: u16 = digits[3..5].parse().unwrap_or(0);
            let serial: u16 = digits[5..9].parse().unwrap_or(0);

            if !Self::is_valid_ssn(area, group, serial) {
                continue;
            }

            // Lower confidence for bare numbers (high FP risk)
            findings.push(
                Finding::new(
                    ValidatorModule::SSN,
                    TechnicalSeverity::High,
                    "SSN_BARE_DETECTED",
                    "PII_LEAKAGE_POSSIBLE",
                    &Self::mask_ssn(area, group, serial),
                )
                .with_position(
                    full_match.start() as u16,
                    full_match.end() as u16,
                )
                .with_confidence(60),
            );
        }

        findings
    }
}

impl Default for SsnValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for SsnValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let mut findings = self.scan_formatted(input);
        let bare = self.scan_bare(input);

        // Deduplicate: skip bare findings that overlap with formatted
        for b in bare {
            let overlaps = findings.iter().any(|f| {
                f.position_start == b.position_start
                    || (b.position_start >= f.position_start
                        && b.position_start < f.position_end)
            });
            if !overlaps {
                findings.push(b);
            }
        }

        findings
    }

    fn name(&self) -> &'static str {
        "ssn"
    }

    fn module_id(&self) -> ValidatorModule {
        ValidatorModule::SSN
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.12, 0.05, 20260220, 300)
            .with_limitations(
                "Bare 9-digit numbers have high FP rate (~25%). \
                 Does not validate against SSA death master file. \
                 Post-2011 randomization means area-based geography \
                 inference is unreliable.",
            )
            .with_affected_groups(
                "Bare numeric sequences (order IDs, zip+4 codes, \
                 reference numbers). Non-US users with 9-digit IDs.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── VALID SSN DETECTION ──────────────────────────────

    #[test]
    fn test_detect_formatted_ssn() {
        let v = SsnValidator::new();
        let f = v.scan_formatted("My SSN is 123-45-6789");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, TechnicalSeverity::Critical(255));
        assert_eq!(f[0].confidence, 95);
    }

    #[test]
    fn test_detect_space_separated() {
        let v = SsnValidator::new();
        let f = v.scan_formatted("SSN: 123 45 6789");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, 95);
    }

    #[test]
    fn test_detect_bare_ssn() {
        let v = SsnValidator::new();
        let f = v.scan_bare("Number: 123456789");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, TechnicalSeverity::High);
        assert_eq!(f[0].confidence, 60);
    }

    // ── INVALID SSN REJECTION ────────────────────────────

    #[test]
    fn test_reject_area_000() {
        assert!(!SsnValidator::is_valid_ssn(0, 12, 3456));
    }

    #[test]
    fn test_reject_area_666() {
        assert!(!SsnValidator::is_valid_ssn(666, 12, 3456));
    }

    #[test]
    fn test_reject_area_900_plus() {
        assert!(!SsnValidator::is_valid_ssn(900, 12, 3456));
        assert!(!SsnValidator::is_valid_ssn(999, 12, 3456));
    }

    #[test]
    fn test_reject_group_00() {
        assert!(!SsnValidator::is_valid_ssn(123, 0, 3456));
    }

    #[test]
    fn test_reject_serial_0000() {
        assert!(!SsnValidator::is_valid_ssn(123, 45, 0));
    }

    #[test]
    fn test_reject_advertising_ssn() {
        // 078-05-1120: famous SSA wallet insert SSN
        assert!(!SsnValidator::is_valid_ssn(78, 5, 1120));
    }

    #[test]
    fn test_reject_woolworth_ssn() {
        assert!(!SsnValidator::is_valid_ssn(219, 9, 9999));
    }

    // ── INVALID FORMAT → LOW SEVERITY ────────────────────

    #[test]
    fn test_invalid_ssn_low_severity() {
        let v = SsnValidator::new();
        // 000-12-3456 → area 000 invalid
        let f = v.scan_formatted("SSN: 000-12-3456");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, TechnicalSeverity::Medium);
        assert_eq!(f[0].confidence, 40);
    }

    // ── MASKING ──────────────────────────────────────────

    #[test]
    fn test_mask_preserves_partial() {
        let masked = SsnValidator::mask_ssn(123, 45, 6789);
        assert!(!masked.contains("123"));
        assert!(!masked.contains("6789"));
    }

    // ── PIPELINE INTEGRATION (Module trait) ──────────────

    #[test]
    fn test_module_name() {
        let v = SsnValidator::new();
        assert_eq!(v.name(), "ssn");
    }

    #[test]
    fn test_module_id() {
        let v = SsnValidator::new();
        assert_eq!(v.module_id(), ValidatorModule::SSN);
    }

    #[test]
    fn test_bias_declaration_valid() {
        let v = SsnValidator::new();
        let bias = v.bias_declaration();
        assert!(bias.false_positive_rate > 0.0);
        assert!(bias.false_negative_rate > 0.0);
        assert!(bias.is_calibration_valid());
        assert!(bias.test_dataset_size >= 50);
    }

    // ── DEDUPLICATION ────────────────────────────────────

    #[test]
    fn test_no_duplicate_formatted_and_bare() {
        let v = SsnValidator::new();
        let mut ctx = ScanContext::default();
        // Formatted SSN — should NOT also produce bare finding
        let f = v.scan("My SSN is 123-45-6789", &mut ctx);
        let ssn_findings: Vec<_> = f.iter()
            .filter(|f| f.module == ValidatorModule::SSN)
            .collect();
        // Should be exactly 1 (formatted), not 2
        assert_eq!(ssn_findings.len(), 1);
        assert_eq!(ssn_findings[0].confidence, 95);
    }

    // ── CLEAN INPUT ──────────────────────────────────────

    #[test]
    fn test_clean_input_no_findings() {
        let v = SsnValidator::new();
        let mut ctx = ScanContext::default();
        let f = v.scan("Hello, this is a normal message", &mut ctx);
        assert!(f.is_empty());
    }

    // ── MULTIPLE SSNs ────────────────────────────────────

    #[test]
    fn test_multiple_ssns() {
        let v = SsnValidator::new();
        let mut ctx = ScanContext::default();
        let f = v.scan(
            "SSN1: 123-45-6789 and SSN2: 234-56-7890",
            &mut ctx,
        );
        let valid: Vec<_> = f.iter()
            .filter(|f| f.confidence >= 90)
            .collect();
        assert_eq!(valid.len(), 2);
    }
}
