//! Ledger Entry v2.3.2
//! Entrada imutável do ledger (384 bytes fixos).
use static_assertions;
use serde::{Deserialize, Serialize};
use crate::core::types::{Action, EthicalVerdict, RiskLevel};

// Serialização customizada para arrays de 196 bytes
mod serde_array_196 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(arr: &[u8; 196], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(arr)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 196], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let mut arr = [0u8; 196];
        let len = bytes.len().min(196);
        arr[..len].copy_from_slice(&bytes[..len]);
        Ok(arr)
    }
}

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
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct LedgerEntry {
    pub entry_id: u64,
    pub _align_padding: u64,
    pub audit_trail_id: u128,
    pub timestamp: u128,
    pub risk_level: RiskLevel,
    pub action: ActionType,
    pub ethical_verdict: EthicalVerdict,
    pub _padding_verdict: [u8; 5],
    pub previous_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub protocol_version: u16,
    pub schema_version: u16,
    pub producer_id: [u8; 32],
    #[serde(with = "serde_array_196")]
    pub _reserved: [u8; 196],
}

static_assertions::const_assert_eq!(std::mem::size_of::<LedgerEntry>(), 384);

impl LedgerEntry {
    pub fn calculate_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.entry_id.to_le_bytes());
        hasher.update(&self.audit_trail_id.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.previous_hash);
        hasher.update(&self._reserved);
        *hasher.finalize().as_bytes()
    }

    pub fn calculate_merkle_root(&mut self, prev_merkle: [u8; 32]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&prev_merkle);
        hasher.update(&self.entry_hash);
        self.merkle_root = *hasher.finalize().as_bytes();
    }

    pub fn finalize(&mut self) {
        self.entry_hash = self.calculate_hash();
    }

    pub fn validate(&self) -> bool {
        self.entry_hash == self.calculate_hash()
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
            merkle_root: [0; 32],
            protocol_version: 1,
            schema_version: 1,
            producer_id: [0; 32],
            _reserved: [0; 196],
        }
    }
}