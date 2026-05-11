//! Output Guard v2.4.1
//! Sanitização de output (XSS, SQL, command injection) + PII masking.
//!
//! INVARIANTE: Nenhum Regex::new() dentro de funções de hot path.
//! Todas as expressões regulares são compiladas uma única vez no boot (lazy_static!).
//! Falhas de compilação causam panic! imediato na inicialização (Fail-Secure).

use std::borrow::Cow;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // ── XSS / Injection patterns (boot-time compilation) ─────
    static ref XSS_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (
            Regex::new(r"(?i)<script.*?>.*?</script>")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [SCRIPT_TAG]: {e}")),
            "SCRIPT_TAG",
        ),
        (
            Regex::new(r"(?i)javascript:")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [JAVASCRIPT_PROTOCOL]: {e}")),
            "JAVASCRIPT_PROTOCOL",
        ),
        (
            Regex::new(r"(?i)on\w+\s*=")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [EVENT_HANDLER]: {e}")),
            "EVENT_HANDLER",
        ),
        (
            Regex::new(r"(?i)<iframe.*?>")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [IFRAME_TAG]: {e}")),
            "IFRAME_TAG",
        ),
        (
            Regex::new(r"(?i)<object.*?>")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [OBJECT_TAG]: {e}")),
            "OBJECT_TAG",
        ),
        (
            Regex::new(r"(?i)<embed.*?>")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [EMBED_TAG]: {e}")),
            "EMBED_TAG",
        ),
        (
            Regex::new(r"(?i)expression\s*\(")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [CSS_EXPRESSION]: {e}")),
            "CSS_EXPRESSION",
        ),
        (
            Regex::new(r"(?i)data:text/html")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [DATA_HTML]: {e}")),
            "DATA_HTML",
        ),
        (
            Regex::new(r"(?i)(union\s+select|select\s+.+\s+from|insert\s+into|delete\s+from|update\s+.+\s+set|drop\s+table)")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [SQL_INJECTION]: {e}")),
            "SQL_INJECTION",
        ),
        (
            Regex::new(r"(?i)(\|\s*sh|\|\s*bash|\|\s*cmd|;\s*sh|;\s*bash|;\s*cmd)")
                .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [COMMAND_INJECTION]: {e}")),
            "COMMAND_INJECTION",
        ),
    ];

    // ── Dangerous tag removal (previously compiled at hot-path) ──
    static ref REMOVE_SCRIPT_TAG: Regex =
        Regex::new(r"(?i)<script.*?>.*?</script>")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [REMOVE_SCRIPT_TAG]: {e}"));
    static ref REMOVE_IFRAME_TAG: Regex =
        Regex::new(r"(?i)<iframe.*?>.*?</iframe>")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [REMOVE_IFRAME_TAG]: {e}"));
    static ref REMOVE_OBJECT_TAG: Regex =
        Regex::new(r"(?i)<object.*?>.*?</object>")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [REMOVE_OBJECT_TAG]: {e}"));
    static ref REMOVE_EMBED_TAG: Regex =
        Regex::new(r"(?i)<embed.*?>.*?</embed>")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [REMOVE_EMBED_TAG]: {e}"));
    static ref REMOVE_APPLET_TAG: Regex =
        Regex::new(r"(?i)<applet.*?>.*?</applet>")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [REMOVE_APPLET_TAG]: {e}"));
    static ref REMOVE_EVENT_ATTRS: Regex =
        Regex::new(r#"(?i)\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)"#)
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [REMOVE_EVENT_ATTRS]: {e}"));

    // ── Dangerous content removal ─────────────────────────────
    static ref DANGEROUS_CONTENT: Regex =
        Regex::new(r#"(?i)<[^>]*(javascript:|data:|vbscript:|expression\(|on\w+\s*=)[^>]*>"#)
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [DANGEROUS_CONTENT]: {e}"));

    // ── HTML tag detection (for analyze_content) ──────────────
    static ref HTML_TAG_DETECT: Regex =
        Regex::new(r"<[^>]+>")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [HTML_TAG_DETECT]: {e}"));

    static ref HTML_SPECIAL_CHARS: [(char, &'static str); 5] = [
        ('&', "&amp;"),
        ('<', "&lt;"),
        ('>', "&gt;"),
        ('"', "&quot;"),
        ('\'', "&#x27;"),
    ];

    // ── PII patterns ──────────────────────────────────────────
    static ref PII_SSN: Regex =
        Regex::new(r"\b(\d{3})[-\s](\d{2})[-\s](\d{4})\b")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [PII_SSN]: {e}"));
    static ref PII_CPF: Regex =
        Regex::new(r"\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [PII_CPF]: {e}"));
    static ref PII_CNPJ: Regex =
        Regex::new(r"\b(\d{2})\.?(\d{3})\.?(\d{3})/?(\d{4})-?(\d{2})\b")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [PII_CNPJ]: {e}"));
    static ref PII_EMAIL: Regex =
        Regex::new(r"\b([a-zA-Z0-9._%+-])([a-zA-Z0-9._%+-]*)@([a-zA-Z0-9])([a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [PII_EMAIL]: {e}"));
    static ref PII_PHONE: Regex =
        Regex::new(r"\b(\d{2})\s?9?\d{4}-?\d{4}\b")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [PII_PHONE]: {e}"));
    static ref PII_CC: Regex =
        Regex::new(r"\b(\d{4})\s?\d{4}\s?\d{4}\s?(\d{4})\b")
            .unwrap_or_else(|e| panic!("BTV invariant violation: Invalid regex literal in OutputGuard [PII_CC]: {e}"));
}

// ─────────────────────────────────────────────────────────────
// PII MASK RESULT
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct PiiMaskResult {
    pub sanitized_text: String,
    pub masked_count: u32,
    pub masked_types: Vec<String>,
}

// ─────────────────────────────────────────────────────────────
// OUTPUT GUARD
// ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct OutputGuard {
    pub escape_html: bool,
    pub strip_dangerous_tags: bool,
    pub validate_urls: bool,
    pub max_length: Option<usize>,
}

impl OutputGuard {
    pub fn new() -> Self {
        Self {
            escape_html: true,
            strip_dangerous_tags: true,
            validate_urls: true,
            max_length: Some(10000),
        }
    }

    /// Sanitiza texto e retorna String (própria ou modificada).
    pub fn sanitize_text(&self, input: &str) -> String {
        let mut result = input.to_string();

        if let Some(max) = self.max_length {
            if result.len() > max {
                result.truncate(max);
                result.push_str("... [TRUNCATED]");
            }
        }

        if self.detect_dangerous_patterns(&result) {
            eprintln!("Dangerous patterns detected, applying strict sanitization");
            result = self.apply_strict_sanitization(&result);
        }

        if self.strip_dangerous_tags {
            result = self.remove_dangerous_tags(&result).to_string();
        }

        if self.escape_html {
            result = self.escape_html_special_chars(&result).to_string();
        }

        result
    }

    pub fn sanitize_url(&self, url: &str) -> Result<String, OutputError> {
        if self.validate_urls && !self.is_potentially_safe_url(url) {
            return Err(OutputError::DangerousUrl);
        }
        Ok(self.sanitize_text(url))
    }

    pub fn sanitize_html(&self, html: &str) -> String {
        let mut result = html.to_string();
        if let Some(max) = self.max_length {
            if result.len() > max {
                result.truncate(max);
                result.push_str("... [TRUNCATED]");
            }
        }
        result = self.remove_dangerous_content(&result).to_string();
        result
    }

    /// Masks PII patterns in text (for LLM output sanitization).
    pub fn mask_pii(&self, input: &str) -> PiiMaskResult {
        let mut result = input.to_string();
        let mut masked_count: u32 = 0;
        let mut masked_types: Vec<String> = Vec::new();

        if PII_CPF.is_match(&result) {
            result = PII_CPF.replace_all(&result, "***.***.***-$4").to_string();
            masked_count += 1;
            masked_types.push("cpf".to_string());
        }

        if PII_CNPJ.is_match(&result) {
            result = PII_CNPJ.replace_all(&result, "**.***.***/$4-$5").to_string();
            masked_count += 1;
            masked_types.push("cnpj".to_string());
        }

        if PII_EMAIL.is_match(&result) {
            result = PII_EMAIL.replace_all(&result, "${1}***@${3}***").to_string();
            masked_count += 1;
            masked_types.push("email".to_string());
        }

        if PII_PHONE.is_match(&result) {
            result = PII_PHONE.replace_all(&result, "$1 ****-****").to_string();
            masked_count += 1;
            masked_types.push("phone".to_string());
        }

        if PII_CC.is_match(&result) {
            result = PII_CC.replace_all(&result, "$1 **** **** $2").to_string();
            masked_count += 1;
            masked_types.push("credit_card".to_string());
        }

        if PII_SSN.is_match(&result) {
            result = PII_SSN.replace_all(&result, |caps: &regex::Captures| {
                format!("***-**-{}", &caps[3])
            }).to_string();
            masked_count += 1;
            masked_types.push("ssn".to_string());
        }

        PiiMaskResult { sanitized_text: result, masked_count, masked_types }
    }

    /// Full sanitization: XSS + PII masking.
    pub fn sanitize_full(&self, input: &str) -> PiiMaskResult {
        let xss_clean = self.sanitize_text(input);
        self.mask_pii(&xss_clean)
    }

    fn detect_dangerous_patterns(&self, text: &str) -> bool {
        XSS_PATTERNS.iter().any(|(re, _)| re.is_match(text))
    }

    /// Hot path: zero Regex compilation — references pre-compiled lazy_static! statics.
    fn remove_dangerous_tags(&self, text: &str) -> Cow<'_, str> {
        let mut result = text.to_string();
        result = REMOVE_SCRIPT_TAG.replace_all(&result, "[REMOVED]").into_owned();
        result = REMOVE_IFRAME_TAG.replace_all(&result, "[REMOVED]").into_owned();
        result = REMOVE_OBJECT_TAG.replace_all(&result, "[REMOVED]").into_owned();
        result = REMOVE_EMBED_TAG.replace_all(&result, "[REMOVED]").into_owned();
        result = REMOVE_APPLET_TAG.replace_all(&result, "[REMOVED]").into_owned();
        result = REMOVE_EVENT_ATTRS.replace_all(&result, "").into_owned();
        Cow::Owned(result)
    }

    /// Hot path: zero Regex compilation — references pre-compiled lazy_static! statics.
    fn remove_dangerous_content(&self, text: &str) -> Cow<'_, str> {
        Cow::Owned(DANGEROUS_CONTENT.replace_all(text, "").into_owned())
    }

    fn escape_html_special_chars<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut result = String::with_capacity(text.len());
        let mut modified = false;
        for c in text.chars() {
            let mut replaced = false;
            for &(special, replacement) in HTML_SPECIAL_CHARS.iter() {
                if c == special {
                    result.push_str(replacement);
                    modified = true;
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                result.push(c);
            }
        }
        if modified { Cow::Owned(result) } else { Cow::Borrowed(text) }
    }

    fn apply_strict_sanitization(&self, text: &str) -> String {
        text.chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || ".!,?".contains(*c))
            .collect()
    }

    fn is_potentially_safe_url(&self, url: &str) -> bool {
        let lower = url.to_lowercase();
        !lower.starts_with("javascript:")
            && !lower.starts_with("data:")
            && !lower.starts_with("vbscript:")
            && !lower.starts_with("file:")
            && !lower.contains("<script")
            && !lower.contains("%3cscript")
    }

    /// Hot path: zero Regex compilation — references pre-compiled lazy_static! statics.
    pub fn analyze_content(&self, text: &str) -> ContentAnalysis {
        let mut analysis = ContentAnalysis {
            length: text.len(),
            has_html_tags: false,
            has_dangerous_patterns: false,
            dangerous_patterns_found: Vec::new(),
            requires_sanitization: false,
        };
        analysis.has_html_tags = HTML_TAG_DETECT.is_match(text);
        for (re, name) in XSS_PATTERNS.iter() {
            if re.is_match(text) {
                analysis.has_dangerous_patterns = true;
                analysis.dangerous_patterns_found.push(name.to_string());
            }
        }
        analysis.requires_sanitization = analysis.has_html_tags || analysis.has_dangerous_patterns;
        analysis
    }
}

impl Default for OutputGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ContentAnalysis {
    pub length: usize,
    pub has_html_tags: bool,
    pub has_dangerous_patterns: bool,
    pub dangerous_patterns_found: Vec<String>,
    pub requires_sanitization: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("Dangerous URL detected")]
    DangerousUrl,
    #[error("Content exceeds maximum allowed length")]
    ContentTooLong,
    #[error("Invalid or malformed content")]
    InvalidContent,
    #[error("Sanitization failed")]
    SanitizationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escaping() {
        let g = OutputGuard::new();
        let out = g.sanitize_text("<div>");
        assert!(out.contains("&lt;div&gt;"));
    }

    #[test]
    fn test_xss_detection() {
        let g = OutputGuard::new();
        let a = g.analyze_content(r#"<img src="x" onerror="alert(1)">"#);
        assert!(a.has_dangerous_patterns);
    }

    #[test]
    fn test_url_sanitization() {
        let g = OutputGuard::new();
        assert!(g.sanitize_url("https://example.com").is_ok());
        assert!(g.sanitize_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_mask_cpf() {
        let g = OutputGuard::new();
        let r = g.mask_pii("CPF: 123.456.789-09");
        assert_eq!(r.sanitized_text, "CPF: ***.***.***-09");
        assert_eq!(r.masked_count, 1);
        assert!(r.masked_types.contains(&"cpf".to_string()));
    }

    #[test]
    fn test_mask_email() {
        let g = OutputGuard::new();
        let r = g.mask_pii("Email: joao@empresa.com");
        assert!(r.sanitized_text.contains("j***@e***"));
        assert!(r.masked_types.contains(&"email".to_string()));
    }

    #[test]
    fn test_mask_credit_card() {
        let g = OutputGuard::new();
        let r = g.mask_pii("Cartao 4532 0151 1283 0366");
        assert!(r.sanitized_text.contains("4532 **** **** 0366"));
        assert!(r.masked_types.contains(&"credit_card".to_string()));
    }

    #[test]
    fn test_mask_multiple() {
        let g = OutputGuard::new();
        let r = g.mask_pii("CPF 123.456.789-09 email joao@test.com");
        assert!(r.masked_count >= 2);
        assert!(r.masked_types.contains(&"cpf".to_string()));
        assert!(r.masked_types.contains(&"email".to_string()));
    }

    #[test]
    fn test_clean_text_no_mask() {
        let g = OutputGuard::new();
        let r = g.mask_pii("Ola, tudo bem?");
        assert_eq!(r.masked_count, 0);
        assert_eq!(r.sanitized_text, "Ola, tudo bem?");
    }

    #[test]
    fn test_mask_ssn() {
        let g = OutputGuard::new();
        let r = g.mask_pii("SSN: 123-45-6789");
        assert_eq!(r.sanitized_text, "SSN: ***-**-6789");
        assert_eq!(r.masked_count, 1);
        assert!(r.masked_types.contains(&"ssn".to_string()));
    }

    #[test]
    fn test_mask_ssn_with_cpf() {
        let g = OutputGuard::new();
        let r = g.mask_pii("SSN 123-45-6789 CPF 123.456.789-09");
        assert!(r.masked_count >= 2);
        assert!(r.masked_types.contains(&"ssn".to_string()));
        assert!(r.masked_types.contains(&"cpf".to_string()));
    }
}
