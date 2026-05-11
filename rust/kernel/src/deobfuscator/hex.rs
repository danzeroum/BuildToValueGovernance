//! Hex Deobfuscator — detecta e decodifica strings hexadecimais longas em inputs.
//! Usado pelo DeobfuscationChain para normalizar entradas ofuscadas.

use lazy_static::lazy_static;
use regex::Regex;

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
