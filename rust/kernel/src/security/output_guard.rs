//! Output Guard v2.3.1
//!
//! Sanitização de output para prevenir ataques XSS, injection e data leakage.
//! Implementa escape de caracteres especiais e validação de conteúdo.
//!
//! Princípio: Todo output para interfaces de usuário ou sistemas externos
//! deve ser sanitizado para prevenir ataques de injeção.

use std::borrow::Cow;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Padrões para detecção de XSS
    static ref XSS_PATTERNS: Vec<(Regex, &'static str)> = vec![
        // Script tags e eventos
        (Regex::new(r"(?i)<script.*?>.*?</script>").unwrap(), "SCRIPT_TAG"),
        (Regex::new(r"(?i)javascript:").unwrap(), "JAVASCRIPT_PROTOCOL"),
        (Regex::new(r"(?i)on\w+\s*=").unwrap(), "EVENT_HANDLER"),

        // Iframes e objetos perigosos
        (Regex::new(r"(?i)<iframe.*?>").unwrap(), "IFRAME_TAG"),
        (Regex::new(r"(?i)<object.*?>").unwrap(), "OBJECT_TAG"),
        (Regex::new(r"(?i)<embed.*?>").unwrap(), "EMBED_TAG"),

        // Expression e data URLs
        (Regex::new(r"(?i)expression\s*\(").unwrap(), "CSS_EXPRESSION"),
        (Regex::new(r"(?i)data:text/html").unwrap(), "DATA_HTML"),

        // SQL injection patterns
        (Regex::new(r"(?i)(union\s+select|select\s+.+\s+from|insert\s+into|delete\s+from|update\s+.+\s+set|drop\s+table)").unwrap(), "SQL_INJECTION"),

        // Command injection
        (Regex::new(r"(?i)(\|\s*sh|\|\s*bash|\|\s*cmd|;\s*sh|;\s*bash|;\s*cmd)").unwrap(), "COMMAND_INJECTION"),
    ];

    // Caracteres HTML especiais que precisam de escape
    static ref HTML_SPECIAL_CHARS: [(char, &'static str); 5] = [
        ('&', "&amp;"),
        ('<', "&lt;"),
        ('>', "&gt;"),
        ('"', "&quot;"),
        ('\'', "&#x27;"),
    ];
}

/// Guardião de output
#[derive(Debug)]
pub struct OutputGuard {
    // Configurações
    pub escape_html: bool,
    pub strip_dangerous_tags: bool,
    pub validate_urls: bool,
    pub max_length: Option<usize>,
}

impl OutputGuard {
    /// Cria um novo guardião com configurações padrão
    pub fn new() -> Self {
        Self {
            escape_html: true,
            strip_dangerous_tags: true,
            validate_urls: true,
            max_length: Some(10000), // 10KB máximo por padrão
        }
    }

    /// Sanitiza texto para output seguro
    pub fn sanitize_text<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut output = Cow::Borrowed(input);

        // Aplica limite de comprimento
        if let Some(max_len) = self.max_length {
            if output.len() > max_len {
                output = Cow::Owned(output[..max_len].to_string() + "... [TRUNCATED]");
            }
        }

        // Detecta padrões perigosos
        if self.detect_dangerous_patterns(&output) {
            log::warn!("Dangerous patterns detected in output, applying strict sanitization");
            output = Cow::Owned(self.apply_strict_sanitization(&output));
        }

        // Remove tags perigosas se configurado
        if self.strip_dangerous_tags {
            output = self.remove_dangerous_tags(&output);
        }

        // Escapa HTML se configurado
        if self.escape_html {
            output = self.escape_html_special_chars(&output);
        }

        output
    }

    /// Sanitiza URL para uso seguro
    pub fn sanitize_url<'a>(&self, url: &'a str) -> Result<Cow<'a, str>, OutputError> {
        // Validação básica de URL
        if self.validate_urls && !self.is_potentially_safe_url(url) {
            return Err(OutputError::DangerousUrl);
        }

        let sanitized = self.sanitize_text(url);
        Ok(sanitized)
    }

    /// Sanitiza conteúdo HTML (preserva HTML seguro)
    pub fn sanitize_html<'a>(&self, html: &'a str) -> Cow<'a, str> {
        let mut output = Cow::Borrowed(html);

        // Aplica limite de comprimento
        if let Some(max_len) = self.max_length {
            if output.len() > max_len {
                output = Cow::Owned(output[..max_len].to_string() + "... [TRUNCATED]");
            }
        }

        // Remove conteúdo perigoso mesmo em HTML
        output = self.remove_dangerous_content(&output);

        output
    }

    /// Detecta padrões perigosos no texto
    fn detect_dangerous_patterns(&self, text: &str) -> bool {
        for (pattern, _name) in XSS_PATTERNS.iter() {
            if pattern.is_match(text) {
                return true;
            }
        }
        false
    }

    /// Remove tags e atributos perigosos
    fn remove_dangerous_tags<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut result = text.to_string();

        // Remove tags de script e iframe
        let dangerous_tags = [
            r"(?i)<script.*?>.*?</script>",
            r"(?i)<iframe.*?>.*?</iframe>",
            r"(?i)<object.*?>.*?</object>",
            r"(?i)<embed.*?>.*?</embed>",
            r"(?i)<applet.*?>.*?</applet>",
        ];

        for pattern in dangerous_tags.iter() {
            let re = Regex::new(pattern).unwrap();
            result = re.replace_all(&result, "[REMOVED]").into_owned();
        }

        // Remove atributos de evento
        let event_pattern = Regex::new(r#"(?i)\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)"#).unwrap();
        result = event_pattern.replace_all(&result, "").into_owned();

        Cow::Owned(result)
    }

    /// Remove conteúdo perigoso (versão mais agressiva)
    fn remove_dangerous_content<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut result = text.to_string();

        // Remove qualquer tag com atributos suspeitos
        let suspicious_attr_pattern = Regex::new(
            r#"(?i)<[^>]*(javascript:|data:|vbscript:|expression\(|on\w+\s*=)[^>]*>"#
        ).unwrap();

        result = suspicious_attr_pattern.replace_all(&result, "").into_owned();

        Cow::Owned(result)
    }

    /// Escapa caracteres HTML especiais
    fn escape_html_special_chars<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut result = String::with_capacity(text.len());
        let mut modified = false;

        for c in text.chars() {
            let mut found = false;
            for &(special, replacement) in HTML_SPECIAL_CHARS.iter() {
                if c == special {
                    result.push_str(replacement);
                    modified = true;
                    found = true;
                    break;
                }
            }

            if !found {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(text)
        }
    }

    /// Aplica sanitização estrita
    fn apply_strict_sanitization(&self, text: &str) -> String {
        // Remove todos os caracteres não alfanuméricos básicos
        text.chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '.' || *c == ',' || *c == '!' || *c == '?')
            .collect()
    }

    /// Verifica se uma URL é potencialmente segura
    fn is_potentially_safe_url(&self, url: &str) -> bool {
        // URLs que começam com javascript:, data:, vbscript: são perigosas
        let dangerous_protocols = [
            "javascript:",
            "data:",
            "vbscript:",
            "file:",
            "ftp:",
        ];

        let url_lower = url.to_lowercase();

        for protocol in dangerous_protocols.iter() {
            if url_lower.starts_with(protocol) {
                return false;
            }
        }

        // Verifica caracteres suspeitos
        if url_lower.contains("<script") || url_lower.contains("%3cscript") {
            return false;
        }

        true
    }

    /// Retorna estatísticas sobre o sanitização
    pub fn analyze_content(&self, text: &str) -> ContentAnalysis {
        let mut analysis = ContentAnalysis {
            length: text.len(),
            has_html_tags: false,
            has_dangerous_patterns: false,
            dangerous_patterns_found: Vec::new(),
            requires_sanitization: false,
        };

        // Detecta tags HTML
        let html_tag_pattern = Regex::new(r"<[^>]+>").unwrap();
        analysis.has_html_tags = html_tag_pattern.is_match(text);

        // Detecta padrões perigosos específicos
        for (pattern, name) in XSS_PATTERNS.iter() {
            if pattern.is_match(text) {
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

/// Análise de conteúdo
#[derive(Debug, Clone)]
pub struct ContentAnalysis {
    pub length: usize,
    pub has_html_tags: bool,
    pub has_dangerous_patterns: bool,
    pub dangerous_patterns_found: Vec<String>,
    pub requires_sanitization: bool,
}

/// Erros de output
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

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escaping() {
        let guard = OutputGuard::new();

        let input = r#"Test <script>alert("XSS")</script> & more"#;
        let sanitized = guard.sanitize_text(input);

        assert!(sanitized.contains("&lt;script&gt;"));
        assert!(sanitized.contains("&quot;XSS&quot;"));
        assert!(sanitized.contains("&amp;"));
        assert!(!sanitized.contains("<script>"));
    }

    #[test]
    fn test_xss_detection() {
        let guard = OutputGuard::new();

        let xss_attempts = vec![
            r#"<script>malicious()</script>"#,
            r#"javascript:alert('xss')"#,
            r#"<img src="x" onerror="alert(1)">"#,
            r#"<iframe src="http://evil.com"></iframe>"#,
        ];

        for attempt in xss_attempts {
            let analysis = guard.analyze_content(attempt);
            assert!(analysis.has_dangerous_patterns);
            assert!(analysis.requires_sanitization);
        }
    }

    #[test]
    fn test_sql_injection_detection() {
        let guard = OutputGuard::new();

        let sql_attempts = vec![
            "SELECT * FROM users",
            "union select password from users",
            "DROP TABLE users",
            "'; DELETE FROM users; --",
        ];

        for attempt in sql_attempts {
            let analysis = guard.analyze_content(attempt);
            assert!(analysis.has_dangerous_patterns);
        }
    }

    #[test]
    fn test_url_sanitization() {
        let guard = OutputGuard::new();

        // URL segura deve passar
        let safe_url = "https://example.com/page";
        assert!(guard.sanitize_url(safe_url).is_ok());

        // URL perigosa deve falhar
        let dangerous_url = "javascript:alert('xss')";
        assert!(matches!(
            guard.sanitize_url(dangerous_url),
            Err(OutputError::DangerousUrl)
        ));
    }

    #[test]
    fn test_content_length_limit() {
        let mut guard = OutputGuard::new();
        guard.max_length = Some(10);

        let long_text = "This is a very long text that exceeds the limit";
        let sanitized = guard.sanitize_text(long_text);

        assert!(sanitized.contains("[TRUNCATED]"));
        assert!(sanitized.len() <= 10 + "... [TRUNCATED]".len());
    }

    #[test]
    fn test_html_sanitization_preserves_safe_content() {
        let guard = OutputGuard::new();

        let safe_html = r#"
            <div class="safe">
                <p>This is <strong>safe</strong> HTML content.</p>
                <a href="https://example.com">Safe link</a>
            </div>
        "#;

        let sanitized = guard.sanitize_html(safe_html);

        // Deve preservar tags seguras
        assert!(sanitized.contains("<div"));
        assert!(sanitized.contains("<p>"));
        assert!(sanitized.contains("<strong>"));
        assert!(sanitized.contains("<a href="));

        // Não deve conter conteúdo perigoso
        assert!(!sanitized.to_lowercase().contains("javascript"));
        assert!(!sanitized.to_lowercase().contains("onclick"));
    }

    #[test]
    fn test_analysis_accuracy() {
        let guard = OutputGuard::new();

        let test_cases = vec![
            ("Plain text", false, false),
            ("Text with <b>HTML</b>", true, false),
            ("<script>alert(1)</script>", true, true),
            ("Normal URL: https://example.com", false, false),
        ];

        for (text, expected_html, expected_dangerous) in test_cases {
            let analysis = guard.analyze_content(text);
            assert_eq!(analysis.has_html_tags, expected_html);
            assert_eq!(analysis.has_dangerous_patterns, expected_dangerous);
        }
    }

    #[test]
    fn test_command_injection_detection() {
        let guard = OutputGuard::new();

        let command_attempts = vec![
            "ls; sh",
            "dir | cmd",
            "cat file | bash",
            "echo test; sh",
        ];

        for attempt in command_attempts {
            let analysis = guard.analyze_content(attempt);
            assert!(analysis.has_dangerous_patterns);
            assert!(analysis.dangerous_patterns_found.contains(&"COMMAND_INJECTION".to_string()));
        }
    }
}