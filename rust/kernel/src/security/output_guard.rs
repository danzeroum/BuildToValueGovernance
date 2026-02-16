//! Output Guard v2.4.0
//! Sanitização de output (XSS, SQL, command injection) + PII masking.

use std::borrow::Cow;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref XSS_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"(?i)<script.*?>.*?</script>").unwrap(), "SCRIPT_TAG"),
        (Regex::new(r"(?i)javascript:").unwrap(), "JAVASCRIPT_PROTOCOL"),
        (Regex::new(r"(?i)on\w+\s*=").unwrap(), "EVENT_HANDLER"),
        (Regex::new(r"(?i)<iframe.*?>").unwrap(), "IFRAME_TAG"),
        (Regex::new(r"(?i)<object.*?>").unwrap(), "OBJECT_TAG"),
        (Regex::new(r"(?i)<embed.*?>").unwrap(), "EMBED_TAG"),
        (Regex::new(r"(?i)expression\s*\(").unwrap(), "CSS_EXPRESSION"),
        (Regex::new(r"(?i)data:text/html").unwrap(), "DATA_HTML"),
        (Regex::new(r"(?i)(union\s+select|select\s+.+\s+from|insert\s+into|delete\s+from|update\s+.+\s+set|drop\s+table)").unwrap(), "SQL_INJECTION"),
        (Regex::new(r"(?i)(\|\s*sh|\|\s*bash|\|\s*cmd|;\s*sh|;\s*bash|;\s*cmd)").unwrap(), "COMMAND_INJECTION"),
    ];

    static ref HTML_SPECIAL_CHARS: [(char, &'static str); 5] = [
        ('&', "&amp;"),
        ('<', "&lt;"),
        ('>', "&gt;"),
        ('"', "&quot;"),
        ('\'', "&#x27;"),
    ];

    // PII patterns for masking
    static ref PII_CPF: Regex = Regex::new(r"\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b").unwrap();
    static ref PII_CNPJ: Regex = Regex::new(r"\b(\d{2})\.?(\d{3})\.?(\d{3})/?(\d{4})-?(\d{2})\b").unwrap();
    static ref PII_EMAIL: Regex = Regex::new(r"\b([a-zA-Z0-9._%+-])([a-zA-Z0-9._%+-]*)@([a-zA-Z0-9])([a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b").unwrap();
    static ref PII_PHONE: Regex = Regex::new(r"\b(\d{2})\s?9?\d{4}-?\d{4}\b").unwrap();
    static ref PII_CC: Regex = Regex::new(r"\b(\d{4})\s?\d{4}\s?\d{4}\s?(\d{4})\b").unwrap();
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

        // CPF: 123.456.789-09 -> ***.***.***-09
        if PII_CPF.is_match(&result) {
            result = PII_CPF.replace_all(&result, "***.***.***-$4").to_string();
            masked_count += 1;
            masked_types.push("cpf".to_string());
        }

        // CNPJ: 11.222.333/0001-81 -> **.***.***/**01-81
        if PII_CNPJ.is_match(&result) {
            result = PII_CNPJ.replace_all(&result, "**.***.***/$4-$5").to_string();
            masked_count += 1;
            masked_types.push("cnpj".to_string());
        }

        // Email: joao@empresa.com -> j***@e***.com
        if PII_EMAIL.is_match(&result) {
            result = PII_EMAIL.replace_all(&result, "${1}***@${3}***").to_string();
            masked_count += 1;
            masked_types.push("email".to_string());
        }

        // Phone: 11 98765-4321 -> 11 ****-****
        if PII_PHONE.is_match(&result) {
            result = PII_PHONE.replace_all(&result, "$1 ****-****").to_string();
            masked_count += 1;
            masked_types.push("phone".to_string());
        }

        // Credit card: 4532 0151 1283 0366 -> 4532 **** **** 0366
        if PII_CC.is_match(&result) {
            result = PII_CC.replace_all(&result, "$1 **** **** $2").to_string();
            masked_count += 1;
            masked_types.push("credit_card".to_string());
        }

        PiiMaskResult {
            sanitized_text: result,
            masked_count,
            masked_types,
        }
    }

    /// Full sanitization: XSS + PII masking.
    pub fn sanitize_full(&self, input: &str) -> PiiMaskResult {
        let xss_clean = self.sanitize_text(input);
        self.mask_pii(&xss_clean)
    }

    fn detect_dangerous_patterns(&self, text: &str) -> bool {
        XSS_PATTERNS.iter().any(|(re, _)| re.is_match(text))
    }

    fn remove_dangerous_tags(&self, text: &str) -> Cow<str> {
        let mut result = text.to_string();
        let dangerous = [
            r"(?i)<script.*?>.*?</script>",
            r"(?i)<iframe.*?>.*?</iframe>",
            r"(?i)<object.*?>.*?</object>",
            r"(?i)<embed.*?>.*?</embed>",
            r"(?i)<applet.*?>.*?</applet>",
        ];
        for pattern in &dangerous {
            let re = Regex::new(pattern).unwrap();
            result = re.replace_all(&result, "[REMOVED]").into_owned();
        }
        let event_re = Regex::new(r#"(?i)\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)"#).unwrap();
        result = event_re.replace_all(&result, "").into_owned();
        Cow::Owned(result)
    }

    fn remove_dangerous_content(&self, text: &str) -> Cow<str> {
        let mut result = text.to_string();
        let suspicious = Regex::new(
            r#"(?i)<[^>]*(javascript:|data:|vbscript:|expression\(|on\w+\s*=)[^>]*>"#
        ).unwrap();
        result = suspicious.replace_all(&result, "").into_owned();
        Cow::Owned(result)
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

    pub fn analyze_content(&self, text: &str) -> ContentAnalysis {
        let mut analysis = ContentAnalysis {
            length: text.len(),
            has_html_tags: false,
            has_dangerous_patterns: false,
            dangerous_patterns_found: Vec::new(),
            requires_sanitization: false,
        };
        let html_tag = Regex::new(r"<[^>]+>").unwrap();
        analysis.has_html_tags = html_tag.is_match(text);
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
}