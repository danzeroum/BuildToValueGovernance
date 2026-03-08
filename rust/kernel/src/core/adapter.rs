//! Input Adapter v1.0.0 — Pipeline Entry (BLAKE3 normalizer, P-035)
//! Normaliza e hasha o input bruto antes do Supply Guard.
//! Zero heap no hot path: BLAKE3 opera sobre slice, output é struct Copy.
//! Fail-secure: input vazio ou oversized → AdaptError (BLOCK upstream).

use crate::core::types::HASH_SIZE;

/// Limite máximo de input em bytes (64 KiB).
pub const MAX_INPUT_BYTES: usize = 65_536;

/// Erros do estágio Adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptError {
    InputTooLarge { size: usize },
    Empty,
}

/// Resultado do Adapter: hash BLAKE3 + tamanho normalizado.
/// Copy: sem heap.
#[derive(Debug, Clone, PartialEq)]
pub struct AdaptedInput {
    /// BLAKE3 hash do input normalizado (trimmed).
    pub blake3_hash: [u8; HASH_SIZE],
    /// Tamanho em bytes do input normalizado.
    pub normalized_len: usize,
}

/// Adapta input bruto: trim → validação de tamanho → hash BLAKE3.
/// Zero heap: BLAKE3 roda sobre slice, output é struct.
pub fn adapt(raw_input: &str) -> Result<AdaptedInput, AdaptError> {
    if raw_input.is_empty() {
        return Err(AdaptError::Empty);
    }
    let normalized = raw_input.trim();
    if normalized.is_empty() {
        return Err(AdaptError::Empty);
    }
    if normalized.len() > MAX_INPUT_BYTES {
        return Err(AdaptError::InputTooLarge { size: normalized.len() });
    }
    let hash = blake3::hash(normalized.as_bytes());
    let blake3_hash = *hash.as_bytes();
    Ok(AdaptedInput { blake3_hash, normalized_len: normalized.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_input_adapts() {
        let ai = adapt("hello world").unwrap();
        assert_eq!(ai.normalized_len, 11);
        assert_ne!(ai.blake3_hash, [0u8; 32]);
    }

    #[test]
    fn empty_string_errors() {
        assert_eq!(adapt(""), Err(AdaptError::Empty));
    }

    #[test]
    fn whitespace_only_errors() {
        assert_eq!(adapt("   \t\n  "), Err(AdaptError::Empty));
    }

    #[test]
    fn trim_produces_same_hash() {
        let r1 = adapt("  hello  ").unwrap();
        let r2 = adapt("hello").unwrap();
        assert_eq!(r1.blake3_hash, r2.blake3_hash);
        assert_eq!(r1.normalized_len, r2.normalized_len);
    }

    #[test]
    fn oversized_input_blocked() {
        let big = "a".repeat(MAX_INPUT_BYTES + 1);
        assert!(matches!(adapt(&big), Err(AdaptError::InputTooLarge { .. })));
    }

    #[test]
    fn max_boundary_allowed() {
        let exact = "a".repeat(MAX_INPUT_BYTES);
        assert!(adapt(&exact).is_ok());
    }

    #[test]
    fn deterministic_hash() {
        let r1 = adapt("deterministic").unwrap();
        let r2 = adapt("deterministic").unwrap();
        assert_eq!(r1.blake3_hash, r2.blake3_hash);
    }

    #[test]
    fn different_inputs_different_hashes() {
        let r1 = adapt("input one").unwrap();
        let r2 = adapt("input two").unwrap();
        assert_ne!(r1.blake3_hash, r2.blake3_hash);
    }
}
