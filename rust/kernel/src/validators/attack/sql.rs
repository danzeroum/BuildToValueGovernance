//! SQL Injection Detector v1.0.0 — ADR-048
//! Zero heap no hot path: sem to_lowercase(), sem String::new()
use crate::core::module::{Module, ScanContext, ScanContextFlags};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

const SQL_PATTERNS: &[&str] = &[
    "select ", "insert ", "update ", "delete ", "drop ",
    "union ",  "truncate ", "exec ",  "execute ", "xp_",
    "'; ",     "\"; ",      "--",     "/*",        "*/",
    "1=1",     "or 1",      "and 1",  "sleep(",    "waitfor ",
    "benchmark(",
];

#[inline]
fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

pub struct SqlInjectionDetector;
impl Default for SqlInjectionDetector { fn default() -> Self { Self } }
impl SqlInjectionDetector { pub fn new() -> Self { Self } }

impl Module for SqlInjectionDetector {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
        let bytes = input.as_bytes();
        let hits = SQL_PATTERNS.iter()
            .filter(|p| contains_ci(bytes, p.as_bytes()))
            .count().min(255) as u8;
        if hits == 0 { return Vec::new(); }
        // Rawls: DBAs with CAP_TRUSTED_ROLE need 3 hits for Critical (vs 2)
        let threshold: u8 = if ctx.flags.has_capability(ScanContextFlags::CAP_TRUSTED_ROLE) { 3 } else { 2 };
        let severity = if hits >= threshold {
            TechnicalSeverity::Critical(200)
        } else {
            TechnicalSeverity::High
        };
        vec![Finding::new(
            ValidatorModule::SqlInjection,
            severity,
            "SQL_PATTERN_MATCH",
            "SQL_INJECTION_ATTEMPT",
            input,
        ).with_confidence((hits.saturating_mul(30)).min(95))]
    }

    fn name(&self) -> &'static str { "sql_injection" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::SqlInjection }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.05, 0.10, 20260520, 500)
            .with_limitations("Keyword-based. May FP on SQL documentation.")
            .with_affected_groups("DBAs, SQL developers.")
    }

    fn explain_decision(&self, input: &str) -> &'static str {
        let bytes = input.as_bytes();
        let hits = SQL_PATTERNS.iter()
            .filter(|p| contains_ci(bytes, p.as_bytes()))
            .count();
        match hits {
            0 => "No SQL injection patterns detected.",
            1 => "One SQL keyword detected — elevated risk. Contestable within 24h.",
            _ => "Multiple SQL keywords detected — Critical. Contestable within 24h.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ScanContext;

    #[test]
    fn detects_drop_table_attack() {
        let d = SqlInjectionDetector::new();
        let mut ctx = ScanContext::default();
        // 3+ hits (select, 1=1, drop, -- ): Critical even with CAP_TRUSTED_ROLE threshold=3
        let findings = d.scan("select * from users where 1=1; DROP TABLE users; -- ", &mut ctx);
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }

    #[test]
    fn passes_plain_text() {
        let d = SqlInjectionDetector::new();
        let mut ctx = ScanContext::default();
        assert!(d.scan("hello world", &mut ctx).is_empty());
    }

    #[test]
    fn trusted_role_raises_threshold() {
        let d = SqlInjectionDetector::new();
        let mut ctx = ScanContext::default();
        ctx.flags.capability_mask = ScanContextFlags::CAP_TRUSTED_ROLE;
        // Single "select " hit → High (not Critical) for trusted role
        let findings = d.scan("select something", &mut ctx);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, TechnicalSeverity::High);
    }

    #[test]
    fn detects_trailing_comment_without_space() {
        let d = SqlInjectionDetector::new();
        let mut ctx = ScanContext::default();
        let findings = d.scan("SELECT * FROM users; DROP TABLE sessions; --", &mut ctx);
        assert!(!findings.is_empty());
        assert!(findings[0].severity.is_critical());
    }
}
