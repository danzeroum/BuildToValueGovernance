//! Base64 Deobfuscator — detecta e decodifica strings Base64 em inputs.
//! Usado pelo DeobfuscationChain para normalizar entradas ofuscadas.


use lazy_static::lazy_static;
use regex::Regex;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;


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
        // 4-char matches are too short to be real base64 payload and produce
        // false positives on common English words (e.g. "Hell", "hell").
        // Require at least 8 chars (2 full 4-char groups = 6 decoded bytes).
        if candidate.len() < 8 { continue; }
        if let Ok(bytes) = B64.decode(candidate) {
            return match String::from_utf8(bytes.clone()) {
                Ok(s)  => Base64Result::Decoded(s),
                Err(_) => Base64Result::DecodedBinary(bytes),
            };
        }
    }
    Base64Result::NotBase64
}


// ---------------------------------------------------------------------------
// Module wrapper — implementa o trait Module para uso no pipeline do Gatekeeper.
// ---------------------------------------------------------------------------

pub struct Base64Detector;

impl Base64Detector {
    pub fn new() -> Self { Self }
}

impl Default for Base64Detector {
    fn default() -> Self { Self::new() }
}

impl Module for Base64Detector {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        match try_decode(input) {
            Base64Result::Decoded(decoded) => vec![
                Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::Low,
                    "DEOBFUSCATOR_BASE64_001",
                    "BASE64_ENCODED_CONTENT",
                    &format!("decoded: {}", &decoded[..decoded.len().min(64)]),
                )
            ],
            Base64Result::DecodedBinary(_) => vec![
                Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::Low,
                    "DEOBFUSCATOR_BASE64_001",
                    "BASE64_ENCODED_BINARY",
                    "non-utf8 binary payload detected",
                )
            ],
            Base64Result::NotBase64 => vec![],
        }
    }

    fn name(&self) -> &'static str { "base64_detector" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Deobfuscator }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.15, 0.05, 20260517, 200)
            .with_limitations("Regex-based; sequências < 8 chars ignoradas para evitar falsos positivos.")
            .with_affected_groups("N/A")
    }
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
