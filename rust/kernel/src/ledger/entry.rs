//! Ledger Entry v2.3.2
//!
//! Define a estrutura imutável de um evento no Ledger.
//! Otimizado para Zero-Copy e alinhamento de memória (repr C).
//!
//! **CHANGELOG v2.3.2**:
//! - ✅ Adicionado campo `ethical_verdict` (v2.4.0 types support)
//! - ✅ Correção de alinhamento u128 (Padding explícito)
//! - ✅ Correção de tamanho total (384 bytes verificados)

use serde::{Deserialize, Serialize};
use crate::core::types::{Action, EthicalVerdict, RiskLevel};
use std::time::{SystemTime, UNIX_EPOCH};

/// Ação tomada pelo sistema (Simplificado para o Ledger)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ActionType {
    Allow = 0,
    Log = 1,
    Educate = 2,
    Redact = 3,
    Block = 4,
}

impl From<Action> for ActionType {
    fn from(action: Action) -> Self {
        match action {
            Action::Allow => ActionType::Allow,
            Action::Log => ActionType::Log,
            Action::Block => ActionType::Block,
            Action::Redact => ActionType::Redact,
        }
    }
}

/// Entrada do Ledger (384 bytes fixos)
///
/// Layout fixo para persistência direta (WAL/S3) e FFI.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct LedgerEntry {
    // === IDENTIFICAÇÃO (48 bytes) ===
    pub entry_id: u64,           // 8 bytes (Sequencial)

    // ✅ FIX: Padding explícito para alinhar o u128 abaixo em 16 bytes
    pub _align_padding: u64,     // 8 bytes

    pub audit_trail_id: u128,    // 16 bytes (UUID v7)
    pub timestamp: u128,         // 16 bytes (Microssegundos UNIX)

    // === VEREDITO (8 bytes) ===
    pub risk_level: RiskLevel,       // 1 byte
    pub action: ActionType,          // 1 byte
    pub ethical_verdict: EthicalVerdict, // 1 byte
    pub _padding_verdict: [u8; 5],   // 5 bytes (Alinhamento)

    // === INTEGRIDADE (64 bytes) ===
    pub previous_hash: [u8; 32],     // 32 bytes (Hash do entry anterior)
    pub entry_hash: [u8; 32],        // 32 bytes (Hash deste entry - BLAKE3)

    // === METADATA (264 bytes) ===
    pub protocol_version: u16,       // 2 bytes
    pub schema_version: u16,         // 2 bytes
    pub producer_id: [u8; 32],       // 32 bytes (ID do componente gerador)

    // ✅ FIX: Reduzido de 236 para 228 para compensar o _align_padding
    #[serde(with = "serde_bytes")]
    pub _reserved: [u8; 228],        // 228 bytes (Expansão futura)
}

// Garantia de tamanho em compile-time
static_assertions::const_assert_eq!(std::mem::size_of::<LedgerEntry>(), 384);

impl LedgerEntry {
    /// Cria uma nova entrada do Ledger (ainda sem hash final)
    pub fn new(
        entry_id: u64,
        audit_trail_id: u128,
        previous_hash: [u8; 32],
        risk: RiskLevel,
        action: Action,
        verdict: EthicalVerdict
    ) -> Self {
        Self {
            entry_id,
            _align_padding: 0, // Inicializa padding
            audit_trail_id,
            timestamp: Self::now_micros(),
            risk_level: risk,
            action: ActionType::from(action),
            ethical_verdict: verdict,
            _padding_verdict: [0; 5],
            previous_hash,
            entry_hash: [0; 32], // Será calculado em finalize()
            protocol_version: 1,
            schema_version: 1,
            producer_id: [0; 32],
            _reserved: [0; 228],
        }
    }

    /// Calcula o hash BLAKE3 deste entry (excluindo o próprio campo entry_hash)
    pub fn calculate_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Identificação
        hasher.update(&self.entry_id.to_le_bytes());
        hasher.update(&self._align_padding.to_le_bytes()); // Inclui padding no hash para determinismo
        hasher.update(&self.audit_trail_id.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());

        // Veredito
        hasher.update(&[self.risk_level as u8]);
        hasher.update(&[self.action as u8]);

        // Serialização manual de Enum para consistência
        let verdict_bytes = bincode::serialize(&self.ethical_verdict).unwrap_or(vec![0]);
        hasher.update(&verdict_bytes);

        hasher.update(&self._padding_verdict);

        // Integridade Anterior
        hasher.update(&self.previous_hash);

        // Metadata
        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.producer_id);
        hasher.update(&self._reserved);

        *hasher.finalize().as_bytes()
    }

    /// Finaliza a entrada calculando e selando o hash
    pub fn finalize(&mut self) {
        self.entry_hash = self.calculate_hash();
    }

    fn now_micros() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros()
    }
}

impl Default for LedgerEntry {
    fn default() -> Self {
        Self {
            entry_id: 0,
            _align_padding: 0,
            audit_trail_id: 0,
            timestamp: 0,
            risk_level: RiskLevel::Safe,
            action: ActionType::Allow,
            ethical_verdict: EthicalVerdict::Pending,
            _padding_verdict: [0; 5],
            previous_hash: [0; 32],
            entry_hash: [0; 32],
            protocol_version: 1,
            schema_version: 1,
            producer_id: [0; 32],
            _reserved: [0; 228],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_entry_size() {
        assert_eq!(std::mem::size_of::<LedgerEntry>(), 384);
    }

    #[test]
    fn test_action_conversion() {
        assert_eq!(ActionType::from(Action::Allow), ActionType::Allow);
        assert_eq!(ActionType::from(Action::Block), ActionType::Block);
    }

    #[test]
    fn test_hashing_consistency() {
        let mut entry = LedgerEntry::default();
        entry.entry_id = 100;

        let hash1 = entry.calculate_hash();
        let hash2 = entry.calculate_hash();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }
}