//! SSTI Detector v1.0.0 — ADR-048 extension
//! Server-Side Template Injection: RCE risk via template engines (Jinja2, Twig, EL, etc.)
//! Distinct from XSS: SSTI executes server-side, severity matches jailbreak (RCE = worst case).
//! Zero heap no hot path: sem to_lowercase(), sem String::new()
use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

// Definite SSTI RCE chains — any match → Critical(220) (server-side code execution)
const SSTI_CRITICAL_PATTERNS: &[&str] = &[
    "__class__.__init__", // Python SSTI introspection chain
    "config.__class__",   // Jinja2-specific SSTI via config object
];

// Template delimiters alone: suspicious but not definitive RCE → High (→ EDUCATE)
const SSTI_EDUCATE_PATTERNS: &[&str] = &[
    "{{",  // Jinja2 / Mustache / Twig expression delimiter
    "${",  // EL / JS template literal
    "#{",  // Ruby / Thymeleaf expression delimiter
];

#[inline]
fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

pub struct SstiDetector;
impl Default for SstiDetector { fn default() -> Self { Self } }
impl SstiDetector { pub fn new() -> Self { Self } }

impl Module for SstiDetector {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let bytes = input.as_bytes();

        // Critical patterns checked first (RCE chains take priority)
        if let Some(pattern) = SSTI_CRITICAL_PATTERNS.iter()
            .find(|p| contains_ci(bytes, p.as_bytes()))
        {
            return vec![Finding::new(
                ValidatorModule::Ssti,
                TechnicalSeverity::Critical(220),
                "SSTI_RCE_PATTERN",
                pattern,
                input,
            ).with_confidence(90)];
        }

        // Educate patterns: template delimiters without RCE chain
        if let Some(pattern) = SSTI_EDUCATE_PATTERNS.iter()
            .find(|p| contains_ci(bytes, p.as_bytes()))
        {
            return vec![Finding::new(
                ValidatorModule::Ssti,
                TechnicalSeverity::High,
                "SSTI_TEMPLATE_DELIMITER",
                pattern,
                input,
            ).with_confidence(60)];
        }

        Vec::new()
    }

    fn name(&self) -> &'static str { "ssti" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Ssti }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.05, 0.10, 20260526, 150)
            .with_limitations("Pattern-based. Template delimiters (High) may FP on documentation. RCE chains (Critical) are highly specific.")
            .with_affected_groups("Template engine users, backend developers.")
    }

    fn explain_decision(&self, input: &str) -> &'static str {
        let bytes = input.as_bytes();
        if SSTI_CRITICAL_PATTERNS.iter().any(|p| contains_ci(bytes, p.as_bytes())) {
            "SSTI RCE chain detected — server-side code execution risk. Critical. Contestable within 24h."
        } else if SSTI_EDUCATE_PATTERNS.iter().any(|p| contains_ci(bytes, p.as_bytes())) {
            "Template delimiter detected — potential SSTI probe. Review intent. Contestable within 24h."
        } else {
            "No SSTI pattern detected."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ScanContext;

    #[test]
    fn detects_jinja2_rce_chain() {
        let d = SstiDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan(
            "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
            &mut ctx,
        );
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }

    #[test]
    fn detects_python_class_introspection() {
        let d = SstiDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan(
            "{{''.__class__.__init__.__globals__['os'].popen('ls').read()}}",
            &mut ctx,
        );
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }

    #[test]
    fn detects_template_delimiter_as_high() {
        let d = SstiDetector::new();
        let mut ctx = ScanContext::default();
        // E8: template expressions without RCE chain → High (not Critical) → EDUCATE
        let findings = d.scan("{{7*7}} ${7*7} #{7*7}", &mut ctx);
        assert!(!findings.is_empty());
        assert!(!findings[0].severity.is_critical());
        assert_eq!(findings[0].severity, TechnicalSeverity::High);
    }

    #[test]
    fn passes_plain_text() {
        let d = SstiDetector::new();
        let mut ctx = ScanContext::default();
        assert!(d.scan("hello world", &mut ctx).is_empty());
    }
}
