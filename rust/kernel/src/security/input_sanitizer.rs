
use unicode_normalization::UnicodeNormalization;
use std::borrow::Cow;

/// Input sanitizer (defense in depth)
pub struct InputSanitizer {
    max_length: usize,
    allow_unicode: bool,
}

impl InputSanitizer {
    pub fn new(max_length: usize) -> Self {
        Self {
            max_length,
            allow_unicode: true,
        }
    }
    
    /// Sanitiza input completo (pipeline)
    pub fn sanitize(&self, input: &str) -> Result<String, SanitizationError> {
        let mut text = Cow::Borrowed(input);
        
        // 1. Length check (prevent DoS)
        if text.len() > self.max_length {
            return Err(SanitizationError::InputTooLarge {
                size: text.len(),
                max: self.max_length,
            });
        }
        
        // 2. Unicode normalization (NFC form)
        text = Cow::Owned(text.nfc().collect::<String>());
        
        // 3. Remove zero-width characters (evasion prevention)
        text = Cow::Owned(self.remove_zero_width(&text));
        
        // 4. Remove control characters (except whitespace)
        text = Cow::Owned(self.remove_control_chars(&text));
        
        // 5. Normalize whitespace
        text = Cow::Owned(self.normalize_whitespace(&text));
        
        // 6. Validate UTF-8 (防止 invalid sequences)
        if !text.is_char_boundary(text.len()) {
            return Err(SanitizationError::InvalidUtf8);
        }
        
        // 7. Check for null bytes (C-string injection prevention)
        if text.contains('\0') {
            return Err(SanitizationError::NullByteDetected);
        }
        
        Ok(text.into_owned())
    }
    
    /// Remove zero-width characters
    fn remove_zero_width(&self, text: &str) -> String {
        text.chars()
            .filter(|&c| {
                !matches!(c,
                    '\u{200B}' |  // Zero-width space
                    '\u{200C}' |  // Zero-width non-joiner
                    '\u{200D}' |  // Zero-width joiner
                    '\u{FEFF}'    // Zero-width no-break space
                )
            })
            .collect()
    }
    
    /// Remove control characters (except tab, newline, carriage return)
    fn remove_control_chars(&self, text: &str) -> String {
        text.chars()
            .filter(|&c| {
                !c.is_control() || matches!(c, '\t' | '\n' | '\r')
            })
            .collect()
    }
    
    /// Normalize whitespace (collapse multiple spaces)
    fn normalize_whitespace(&self, text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SanitizationError {
    #[error("Input too large: {size} bytes (max: {max})")]
    InputTooLarge { size: usize, max: usize },
    
    #[error("Invalid UTF-8 encoding")]
    InvalidUtf8,
    
    #[error("Null byte detected (possible injection)")]
    NullByteDetected,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_width_removal() {
        let sanitizer = InputSanitizer::new(1024);
        
        // CPF with zero-width spaces
        let input = "123\u{200B}.456\u{200B}.789\u{200B}-09";
        let output = sanitizer.sanitize(input).unwrap();
        
        assert_eq!(output, "123.456.789-09");
    }
    
    #[test]
    fn test_control_char_removal() {
        let sanitizer = InputSanitizer::new(1024);
        
        // Text with control characters
        let input = "Hello\x00World\x01Test";
        let result = sanitizer.sanitize(input);
        
        // Should fail due to null byte
        assert!(result.is_err());
    }
    
    #[test]
    fn test_length_limit() {
        let sanitizer = InputSanitizer::new(10);
        
        let input = "This is a very long text";
        let result = sanitizer.sanitize(input);
        
        assert!(matches!(result, Err(SanitizationError::InputTooLarge { .. })));
    }
}