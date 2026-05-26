//! XSS Detector v1.0.0 — ADR-048 extension
//! Detects DOM/HTML injection vectors: event handlers, eval-based patterns, cookie theft.
//! Zero heap no hot path: sem to_lowercase(), sem String::new()
use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

// Definite XSS attack vectors — any single match → Critical(180)
const XSS_CRITICAL_PATTERNS: &[&str] = &[
    "onerror=",        // <img src=x onerror=alert(1)>
    "onload=",         // <svg onload=fetch(...)>
    "eval(atob",       // eval(atob('base64-encoded-payload'))
    "document.cookie", // cookie theft: document.cookie = ...
];

#[inline]
fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

pub struct XssDetector;
impl Default for XssDetector { fn default() -> Self { Self } }
impl XssDetector { pub fn new() -> Self { Self } }

impl Module for XssDetector {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let bytes = input.as_bytes();
        let matched = XSS_CRITICAL_PATTERNS.iter()
            .find(|p| contains_ci(bytes, p.as_bytes()));
        let Some(pattern) = matched else { return Vec::new(); };
        vec![Finding::new(
            ValidatorModule::Xss,
            TechnicalSeverity::Critical(180),
            "XSS_PATTERN",
            pattern,
            input,
        ).with_confidence(85)]
    }

    fn name(&self) -> &'static str { "xss" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Xss }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.03, 0.15, 20260526, 250)
            .with_limitations("Pattern-based event-handler detection. May FP on HTML documentation with inline examples.")
            .with_affected_groups("Frontend developers, security educators.")
    }

    fn explain_decision(&self, input: &str) -> &'static str {
        let bytes = input.as_bytes();
        let matched = XSS_CRITICAL_PATTERNS.iter()
            .any(|p| contains_ci(bytes, p.as_bytes()));
        if matched {
            "XSS pattern matched — DOM injection vector detected. Critical. Contestable within 24h."
        } else {
            "No XSS pattern detected."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ScanContext;

    #[test]
    fn detects_onerror_handler() {
        let d = XssDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan("<img src=x onerror=alert(1)>", &mut ctx);
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }

    #[test]
    fn detects_onload_handler() {
        let d = XssDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan("<svg onload=fetch(atob(url))>", &mut ctx);
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }

    #[test]
    fn detects_eval_atob() {
        let d = XssDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan("eval(atob('Y29uc29sZS5sb2coJ2hhY2snKQ=='))", &mut ctx);
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }

    #[test]
    fn detects_document_cookie() {
        let d = XssDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan("document.cookie = document.cookie + location.href", &mut ctx);
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }

    #[test]
    fn passes_educational_xss_article() {
        let d = XssDetector::new();
        let mut ctx = ScanContext::default();
        // G4: educational mention of XSS without actual attack vectors
        assert!(d.scan(
            "Cross-site scripting (XSS) is a web vulnerability explained in OWASP",
            &mut ctx,
        ).is_empty());
    }

    #[test]
    fn passes_eval_without_atob() {
        let d = XssDetector::new();
        let mut ctx = ScanContext::default();
        // G6: eval mentioned in educational context without base64 payload
        assert!(d.scan(
            "In Python, eval() evaluates a string as code. Avoid using it unsafely.",
            &mut ctx,
        ).is_empty());
    }
}
