//! Finding Definition
//!
//! Estrutura que representa uma violação ou detecção individual.
//! Otimizada para FFI e Zero-Copy (layout C, tamanho fixo).
//!
//! **CHANGELOG**:
//! - Estabilização v2.3.2: Removido campo 'details', adicionado 'matched_text' fixo [u8; 64].
//! - Ajuste de padding para alinhamento de 8 bytes (Total: 144 bytes).
//! - ✅ Fix: Adicionado serde_bytes para matched_text.

use serde::{Deserialize, Serialize};
use crate::core::types::{TechnicalSeverity, ValidatorModule};

/// Finding individual (144 bytes fixos)
///
/// Representa uma violação detectada por um módulo específico.
/// Layout de memória fixo para garantir compatibilidade FFI e alocação na stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct Finding {
    // === METADATA (8 bytes) ===
    pub module: ValidatorModule,      // 1 byte
    pub severity: TechnicalSeverity,  // 2 bytes (Enum discriminante + u8 payload)
    pub confidence: u8,               // 1 byte
    pub position_start: u16,          // 2 bytes
    pub position_end: u16,            // 2 bytes

    // === CLASSIFICAÇÃO (64 bytes) ===
    /// ID único da regra (ex: "VALIDATORS_CPF_001")
    pub rule_id: [u8; 32],

    /// Categoria da ameaça (ex: "PII_LEAKAGE")
    pub threat_category: [u8; 32],

    // === EVIDÊNCIA (64 bytes) ===
    /// Snippet do texto que causou o match (truncado)
    /// ✅ CORREÇÃO: serde_bytes necessário para arrays > 32 bytes
    #[serde(with = "serde_bytes")]
    pub matched_text: [u8; 64],

    // === ALINHAMENTO (8 bytes) ===
    /// Padding explícito para completar 144 bytes
    pub _padding: [u8; 8],
}

// Garantia de tamanho em compile-time
static_assertions::const_assert_eq!(std::mem::size_of::<Finding>(), 144);

impl Finding {
    /// Cria um novo finding com valores padrão e strings truncadas para caber nos arrays fixos
    pub fn new(
        module: ValidatorModule,
        severity: TechnicalSeverity,
        rule_id: &str,
        threat_category: &str,
        matched_text: &str,
    ) -> Self {
        Self {
            module,
            severity,
            confidence: 0,
            position_start: 0,
            position_end: 0,
            rule_id: Self::str_to_fixed(rule_id),
            threat_category: Self::str_to_fixed(threat_category),
            matched_text: Self::str_to_fixed_64(matched_text),
            _padding: [0u8; 8],
        }
    }

    /// Cria um finding vazio (zerado)
    pub fn empty() -> Self {
        Self {
            module: ValidatorModule::Unknown,
            severity: TechnicalSeverity::Info,
            confidence: 0,
            position_start: 0,
            position_end: 0,
            rule_id: [0; 32],
            threat_category: [0; 32],
            matched_text: [0; 64],
            _padding: [0; 8],
        }
    }

    // === Builder Pattern Methods ===

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_position(mut self, start: u16, end: u16) -> Self {
        self.position_start = start;
        self.position_end = end;
        self
    }

    pub fn with_matched_text(mut self, text: &str) -> Self {
        self.matched_text = Self::str_to_fixed_64(text);
        self
    }

    // === Helpers ===

    /// Serializa para bytes de forma segura (para hashing/FFI)
    pub fn to_bytes(&self) -> [u8; 144] {
        unsafe {
            let mut bytes = [0u8; 144];
            let ptr = self as *const Finding as *const u8;
            std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), std::mem::size_of::<Finding>());
            bytes
        }
    }

    fn str_to_fixed<const N: usize>(s: &str) -> [u8; N] {
        let mut buf = [0u8; N];
        let bytes = s.as_bytes();
        let len = bytes.len().min(N);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }

    fn str_to_fixed_64(s: &str) -> [u8; 64] {
        Self::str_to_fixed::<64>(s)
    }

    pub fn rule_id_str(&self) -> String {
        Self::fixed_to_string(&self.rule_id)
    }

    fn fixed_to_string(buf: &[u8]) -> String {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).to_string()
    }
}

impl Default for Finding {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_size_invariant() {
        assert_eq!(std::mem::size_of::<Finding>(), 144);
    }
}