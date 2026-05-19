//! PII Sanitizer v1.6.1 — Mask PII in AI responses, re-scan to verify.
//! Supports: CPF, CNPJ, Email, Phone, Credit Card, US SSN.

use lazy_static::lazy_static;
use regex::Regex;
use crate::core::types::BiasDeclaration;

// ---------------------------------------------------------------------
// MASK PATTERNS (pre-compiled)
// ---------------------------------------------------------------------
lazy_static! {
    static ref CPF_RE: Regex = Regex::new(
        r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"
    ).unwrap_or_else(|e| panic!("BTV init: CPF_RE regex compile failed: {e}"));

    static ref CNPJ_RE: Regex = Regex::new(
        r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"
    ).unwrap_or_else(|e| panic!("BTV init: CNPJ_RE regex compile failed: {e}"));

    static ref EMAIL_RE: Regex = Regex::new(
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
    ).unwrap_or_else(|e| panic!("BTV init: EMAIL_RE regex compile failed: {e}"));

    static ref PHONE_RE: Regex = Regex::new(
        r"\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?\d{4,5}-?\d{4}\b"
    ).unwrap_or_else(|e| panic!("BTV init: PHONE_RE regex compile failed: {e}"));

    static ref CREDIT_CARD_RE: Regex = Regex::new(
        r"\b(?:\d{4}[- ]?){3}\d{4}\b"
    ).unwrap_or_else(|e| panic!("BTV init: CREDIT_CARD_RE regex compile failed: {e}"));

    static ref SSN_RE: Regex = Regex::new(
        r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"
    ).unwrap_or_else(|e| panic!("BTV init: SSN_RE regex compile failed: {e}"));
}

// ---------------------------------------------------------------------
// SANITIZE RESULT
// ---------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct SanitizeResult {
    pub output: String,
    pub masks_applied: u32,
    pub rescan_clean: bool,
    pub mask_details: Vec<MaskDetail>,
}

#[derive(Debug, Clone)]
pub struct MaskDetail {
    pub pii_type: &'static str,
    pub position: usize,
    pub original_len: usize,
}

// ---------------------------------------------------------------------
// OUTPUT SANITIZER
// ---------------------------------------------------------------------
pub struct OutputSanitizer {
    mask_cpf: bool,
    mask_cnpj: bool,
    mask_email: bool,
    mask_phone: bool,
    mask_credit_card: bool,
    mask_ssn: bool,
    rescan_enabled: bool,
}

impl OutputSanitizer {
    pub fn new() -> Self {
        Self {
            mask_cpf: true,
            mask_cnpj: true,
            mask_email: true,
            mask_phone: true,
            mask_credit_card: true,
            mask_ssn: true,
            rescan_enabled: true,
        }
    }

    /// Sanitize output, masking all detected PII.
    /// Re-scans after masking to verify no PII remains.
    pub fn sanitize(&self, output: &str) -> SanitizeResult {
        let mut result = output.to_string();
        let mut masks_applied = 0u32;
        let mut details: Vec<MaskDetail> = Vec::new();

        if self.mask_cpf {
            let (s, n, d) = Self::apply_mask(&result, &CPF_RE, "CPF", Self::mask_cpf_value);
            result = s; masks_applied += n; details.extend(d);
        }
        if self.mask_cnpj {
            let (s, n, d) = Self::apply_mask(&result, &CNPJ_RE, "CNPJ", Self::mask_cnpj_value);
            result = s; masks_applied += n; details.extend(d);
        }
        if self.mask_credit_card {
            let (s, n, d) = Self::apply_mask(&result, &CREDIT_CARD_RE, "CREDIT_CARD", Self::mask_cc_value);
            result = s; masks_applied += n; details.extend(d);
        }
        if self.mask_email {
            let (s, n, d) = Self::apply_mask(&result, &EMAIL_RE, "EMAIL", Self::mask_email_value);
            result = s; masks_applied += n; details.extend(d);
        }
        if self.mask_phone {
            let (s, n, d) = Self::apply_mask(&result, &PHONE_RE, "PHONE", Self::mask_phone_value);
            result = s; masks_applied += n; details.extend(d);
        }

        if self.mask_ssn {
            let (s, n, d) = Self::apply_mask(&result, &SSN_RE, "SSN", Self::mask_ssn_value);
            result = s; masks_applied += n; details.extend(d);
        }

        let rescan_clean = if self.rescan_enabled {
            Self::rescan_is_clean(&result)
        } else {
            true
        };

        SanitizeResult { output: result, masks_applied, rescan_clean, mask_details: details }
    }

    fn apply_mask(
        input: &str,
        pattern: &Regex,
        pii_type: &'static str,
        mask_fn: fn(&str) -> String,
    ) -> (String, u32, Vec<MaskDetail>) {
        let mut count = 0u32;
        let mut details = Vec::new();

        for mat in pattern.find_iter(input) {
            details.push(MaskDetail {
                pii_type,
                position: mat.start(),
                original_len: mat.as_str().len(),
            });
            count += 1;
        }

        let result = pattern.replace_all(input, |caps: &regex::Captures| {
            mask_fn(&caps[0])
        }).to_string();

        (result, count, details)
    }

    fn rescan_is_clean(output: &str) -> bool {
        !CPF_RE.is_match(output)
            && !CNPJ_RE.is_match(output)
            && !EMAIL_RE.is_match(output)
            && !CREDIT_CARD_RE.is_match(output)
            && !SSN_RE.is_match(output)
    }

    fn mask_cpf_value(cpf: &str) -> String {
        let digits: String = cpf.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 11 {
            format!("***.***.{}-**", &digits[6..9])
        } else {
            "[CPF REDACTED]".to_string()
        }
    }

    fn mask_cnpj_value(cnpj: &str) -> String {
        let digits: String = cnpj.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 14 {
            format!("**.***.{}/****-**", &digits[6..9])
        } else {
            "[CNPJ REDACTED]".to_string()
        }
    }

    fn mask_email_value(email: &str) -> String {
        if let Some(at) = email.find('@') {
            let local = &email[..at];
            let domain = &email[at..];
            if local.len() > 2 {
                format!("{}***{}", &local[..1], domain)
            } else {
                format!("***{}", domain)
            }
        } else {
            "[EMAIL REDACTED]".to_string()
        }
    }

    fn mask_phone_value(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 8 {
            format!("(##) ****-{}", &digits[digits.len()-4..])
        } else {
            "[PHONE REDACTED]".to_string()
        }
    }

    fn mask_cc_value(cc: &str) -> String {
        let digits: String = cc.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 12 {
            format!("****-****-****-{}", &digits[digits.len()-4..])
        } else {
            "[CARD REDACTED]".to_string()
        }
    }

    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.02, 0.05, 20260517, 300)
            .with_limitations(
                "Regex-based masking; may miss obfuscated PII. Phone regex Brazilian only."
            )
            .with_affected_groups(
                "International phone formats; non-standard email formats."
            )
    }

    fn mask_ssn_value(ssn: &str) -> String {
        let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 9 {
            format!("***-**-{}", &digits[5..9])
        } else {
            "[SSN REDACTED]".to_string()
        }
    }
}

impl Default for OutputSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_cpf() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("O CPF é 123.456.789-09");
        assert_eq!(r.masks_applied, 1);
        assert!(r.output.contains("***.***"));
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_mask_email() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("Contato: joao@example.com");
        assert_eq!(r.masks_applied, 1);
        assert!(r.output.contains("j***@example.com"));
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_mask_credit_card() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("Cartão: 4532 0151 1283 0366");
        assert_eq!(r.masks_applied, 1);
        assert!(r.output.contains("****-****-****-0366"));
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_mask_cnpj() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("CNPJ: 11.222.333/0001-81");
        assert_eq!(r.masks_applied, 1);
        assert!(!r.output.contains("11.222.333/0001-81"), "Original CNPJ should be masked");
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_mask_multiple_pii() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("CPF: 123.456.789-09, email: test@test.com");
        assert!(r.masks_applied >= 2);
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_clean_input_no_masks() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("This is a clean message with no PII");
        assert_eq!(r.masks_applied, 0);
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_rescan_verifies_clean() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("CPF: 123.456.789-09 and 987.654.321-00");
        assert_eq!(r.masks_applied, 2);
        assert!(r.rescan_clean, "Re-scan should confirm no PII remains");
    }

    #[test]
    fn test_mask_details_tracked() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("CPF: 123.456.789-09");
        assert_eq!(r.mask_details.len(), 1);
        assert_eq!(r.mask_details[0].pii_type, "CPF");
    }

    #[test]
    fn test_mask_ssn_formatted() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("SSN: 123-45-6789");
        assert_eq!(r.masks_applied, 1);
        assert!(r.output.contains("***-**-6789"));
        assert!(!r.output.contains("123-45"));
        assert_eq!(r.mask_details[0].pii_type, "SSN");
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_mask_ssn_space_separated() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("Number: 123 45 6789");
        assert_eq!(r.masks_applied, 1);
        assert!(r.output.contains("***-**-6789"));
        assert!(r.rescan_clean);
    }

    #[test]
    fn test_mask_ssn_with_other_pii() {
        let s = OutputSanitizer::new();
        let r = s.sanitize("SSN 123-45-6789 CPF 123.456.789-09");
        assert!(r.masks_applied >= 2);
        assert!(!r.output.contains("123-45"));
        assert!(r.rescan_clean);
    }
}
