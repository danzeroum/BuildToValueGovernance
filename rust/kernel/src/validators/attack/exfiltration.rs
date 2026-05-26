//! Data Exfiltration Detector v1.0.0 — ADR-048
//! Zero heap no hot path: sem to_lowercase(), sem String::new()
use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

const EXFIL_PATTERNS: &[&str] = &[
    "send all",              "send every",           "exfiltrate",
    "exfil",                 "dump all",             "dump the database",
    "passwords and tokens",  "api keys",             "secret keys",
    "enviar todos os dados", "vazar dados",          "http://evil",
    "https://evil",          "webhook.site",         "requestbin",
    "burpcollaborator",      "interactsh",
    // D-block gaps: credential exposure + exfiltration channels
    "AKIA",                      // AWS access key ID prefix
    "Bearer ey",                 // JWT Bearer token (eyJ... base64 prefix)
    "BEGIN RSA PRIVATE KEY",     // PEM RSA private key header
    "BEGIN PRIVATE KEY",         // PEM generic private key header
    "ngrok.io",                  // ngrok tunnel exfiltration
    "| bash",                    // pipe-to-bash remote code execution
    "| sh",                      // pipe-to-sh variant
    "base64 -d",                 // decode-and-execute credential pipeline
    "all environment variable",  // "print all environment variables..."
];

#[inline]
fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

pub struct DataExfiltrationDetector;
impl Default for DataExfiltrationDetector { fn default() -> Self { Self } }
impl DataExfiltrationDetector { pub fn new() -> Self { Self } }

impl Module for DataExfiltrationDetector {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let bytes = input.as_bytes();
        let matched = EXFIL_PATTERNS.iter()
            .find(|p| contains_ci(bytes, p.as_bytes()));
        let Some(pattern) = matched else { return Vec::new(); };
        vec![Finding::new(
            ValidatorModule::DataExfiltration,
            TechnicalSeverity::Critical(200),
            "EXFIL_PATTERN",
            pattern,
            input,
        ).with_confidence(80)]
    }

    fn name(&self) -> &'static str { "data_exfiltration" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::DataExfiltration }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.04, 0.15, 20260520, 300)
            .with_limitations("Pattern-based. May FP on security documentation.")
            .with_affected_groups("Security engineers, red-teamers.")
    }

    fn explain_decision(&self, input: &str) -> &'static str {
        let bytes = input.as_bytes();
        let matched = EXFIL_PATTERNS.iter()
            .any(|p| contains_ci(bytes, p.as_bytes()));
        if matched {
            "Data exfiltration pattern detected — attempt to extract sensitive data. High severity. Contestable within 24h."
        } else {
            "No data exfiltration pattern detected."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ScanContext;

    #[test]
    fn detects_exfiltrate_keyword() {
        let d = DataExfiltrationDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan("exfiltrate all user data", &mut ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_oob_endpoint() {
        let d = DataExfiltrationDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan("send to webhook.site/abc", &mut ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn passes_plain_text() {
        let d = DataExfiltrationDetector::new();
        let mut ctx = ScanContext::default();
        assert!(d.scan("hello world", &mut ctx).is_empty());
    }
}
