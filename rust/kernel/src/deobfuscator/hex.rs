//! Hex Deobfuscator — detecta e decodifica strings hexadecimais longas em inputs.
//! Usado pelo DeobfuscationChain para normalizar entradas ofuscadas.

use lazy_static::lazy_static;
use regex::Regex;

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;

lazy_static! {
    static ref HEX_REGEX: Regex = Regex::new(
        r"(?:0x)?[0-9a-fA-F]{16,}"
    ).unwrap_or_else(|e| panic!("BTV init: HEX_REGEX compile failed: {e}"));
}

/// Resultado da tentativa de decodificação hex.
#[derive(Debug, Clone, PartialEq)]
pub enum HexResult {
    /// Input decodificado com sucesso para UTF-8 válido.
    Decoded(String),
    /// Decodificado para bytes mas não é UTF-8 válido.
    DecodedBinary(Vec<u8>),
    /// Nenhuma sequência hex válida encontrada.
    NotHex,
}

/// Tenta decodificar a primeira correspondência hex válida no input.
pub fn try_decode(input: &str) -> HexResult {
    for mat in HEX_REGEX.find_iter(input) {
        let candidate = mat.as_str().trim_start_matches("0x");
        if candidate.len() % 2 != 0 { continue; }
        if let Ok(bytes) = hex::decode(candidate) {
            return match String::from_utf8(bytes.clone()) {
                Ok(s)  => HexResult::Decoded(s),
                Err(_) => HexResult::DecodedBinary(bytes),
            };
        }
    }
    HexResult::NotHex
}

// ---------------------------------------------------------------------------
// Module wrapper — implementa o trait Module para uso no pipeline do Gatekeeper.
// ---------------------------------------------------------------------------

pub struct HexDecoder;

impl HexDecoder {
    pub fn new() -> Self { Self }
}

impl Default for HexDecoder {
    fn default() -> Self { Self::new() }
}

impl Module for HexDecoder {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        match try_decode(input) {
            HexResult::Decoded(decoded) => vec![
                Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::Low,
                    "DEOBFUSCATOR_HEX_001",
                    "HEX_ENCODED_CONTENT",
                    &format!("decoded: {}", &decoded[..decoded.len().min(64)]),
                )
            ],
            HexResult::DecodedBinary(_) => vec![
                Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::Low,
                    "DEOBFUSCATOR_HEX_001",
                    "HEX_ENCODED_BINARY",
                    "non-utf8 binary payload detected",
                )
            ],
            HexResult::NotHex => vec![],
        }
    }

    fn name(&self) -> &'static str { "hex_decoder" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Deobfuscator }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.08, 0.10, 20260517, 150)
            .with_limitations("Requer sequência par >=16 chars; ignora hex curto.")
            .with_affected_groups("N/A")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_hello() {
        assert_eq!(
            try_decode("48656c6c6f20576f726c64"),
            HexResult::Decoded("Hello World".to_string())
        );
    }

    #[test]
    fn test_not_hex() {
        assert_eq!(try_decode("hello plain text"), HexResult::NotHex);
    }

    #[test]
    fn test_decode_with_0x_prefix() {
        assert_eq!(
            try_decode("0x48656c6c6f20576f726c64"),
            HexResult::Decoded("Hello World".to_string())
        );
    }
}
