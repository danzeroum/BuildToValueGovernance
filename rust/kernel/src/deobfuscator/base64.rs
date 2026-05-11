//! Base64 Deobfuscator — detecta e decodifica strings Base64 em inputs.
//! Usado pelo DeobfuscationChain para normalizar entradas ofuscadas.

use lazy_static::lazy_static;
use regex::Regex;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

lazy_static! {
    static ref BASE64_REGEX: Regex = Regex::new(
        r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    ).unwrap_or_else(|e| panic!("BTV init: BASE64_REGEX compile failed: {e}"));
}

/// Resultado da tentativa de decodificação Base64.
#[derive(Debug, Clone, PartialEq)]
pub enum Base64Result {
    /// Input decodificado com sucesso para UTF-8 válido.
    Decoded(String),
    /// Decodificado para bytes mas não é UTF-8 válido.
    DecodedBinary(Vec<u8>),
    /// Nenhuma sequência Base64 válida encontrada.
    NotBase64,
}

/// Tenta decodificar a primeira correspondência Base64 válida no input.
pub fn try_decode(input: &str) -> Base64Result {
    for mat in BASE64_REGEX.find_iter(input) {
        let candidate = mat.as_str();
        if candidate.len() < 4 { continue; }
        if let Ok(bytes) = B64.decode(candidate) {
            return match String::from_utf8(bytes.clone()) {
                Ok(s)  => Base64Result::Decoded(s),
                Err(_) => Base64Result::DecodedBinary(bytes),
            };
        }
    }
    Base64Result::NotBase64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hello() {
        assert_eq!(try_decode("SGVsbG8="), Base64Result::Decoded("Hello".to_string()));
    }

    #[test]
    fn test_not_base64() {
        assert_eq!(try_decode("hello world plain text"), Base64Result::NotBase64);
    }

    #[test]
    fn test_decode_embedded() {
        let input = "prefix SGVsbG8= suffix";
        assert_eq!(try_decode(input), Base64Result::Decoded("Hello".to_string()));
    }
}
