//! Ledger Entry v2.3.2
//! Entrada imutável do ledger (384 bytes fixos).
//! v2.4.0: verdict_id [u8;32] adicionado (ADR-043), _reserved 196→164.
use static_assertions;
use serde::{Deserialize, Serialize};
use crate::core::types::{Action, EthicalVerdict, RiskLevel};
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Serialização customizada para arrays de 196 bytes
mod serde_array_164 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(arr: &[u8; 164], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(arr)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 164], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let mut arr = [0u8; 164];
        let len = bytes.len().min(164);
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
    Report = 5,
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
    pub verdict_id: [u8; 32],
    pub _padding_verdict: [u8; 5],
    pub previous_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub protocol_version: u16,
    pub schema_version: u16,
    pub producer_id: [u8; 32],
    #[serde(with = "serde_array_164")]
    pub _reserved: [u8; 164],
}

static_assertions::const_assert_eq!(size_of::<LedgerEntry>(), 384);

impl LedgerEntry {
    /// Computa verdict_id = HMAC-SHA256(key, evidence_hash ‖ action_u8 ‖ trail_id)
    /// ADR-043: identidade determinística e verificável do veredicto.
    /// Zero heap: operações sobre arrays fixos na stack.
    pub fn compute_verdict_id(
        evidence_hash: &[u8; 32],
        ethical_verdict: EthicalVerdict,
        trail_id: u64,
        signing_key: &[u8],
    ) -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;
        const FALLBACK_HMAC_KEY: [u8; 32] = [0u8; 32];
        let mut mac = HmacSha256::new_from_slice(signing_key)
            .unwrap_or_else(|_| {
                HmacSha256::new_from_slice(&FALLBACK_HMAC_KEY)
                    .unwrap_or_else(|_| panic!("BUG: HMAC-SHA256 rejeitou [0u8;32] — impossível por spec"))
            });
        mac.update(evidence_hash);
        mac.update(&[ethical_verdict as u8]);
        mac.update(&trail_id.to_le_bytes());
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

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

    /// Finaliza entrada: computa entry_hash e verdict_id.
    /// Em produção, passar signing_key via Policy (ADR-042).
    /// Chave zero usada como default seguro — verdict_id ainda verificável internamente.
    pub fn finalize(&mut self) {
        self.entry_hash = self.calculate_hash();
        self.verdict_id = Self::compute_verdict_id(
            &self.entry_hash,
            self.ethical_verdict,
            self.entry_id,
            &[0u8; 32],
        );
    }

    /// Finaliza com chave de assinatura do operador (produção).
    pub fn finalize_with_key(&mut self, signing_key: &[u8]) {
        self.entry_hash = self.calculate_hash();
        self.verdict_id = Self::compute_verdict_id(
            &self.entry_hash,
            self.ethical_verdict,
            self.entry_id,
            signing_key,
        );
    }

    /// Valida entry_hash e verdict_id (com chave zero — padrão interno).
    pub fn validate(&self) -> bool {
        if self.entry_hash != self.calculate_hash() {
            return false;
        }
        let expected_vid = Self::compute_verdict_id(
            &self.entry_hash,
            self.ethical_verdict,
            self.entry_id,
            &[0u8; 32],
        );
        self.verdict_id == expected_vid
    }

    // ── ADR-060/062/064: pack bias + regime + explanation into _reserved ─────
    // Layout within _reserved[164]:
    //   [0..4]   — bias_fpr (f32 LE)
    //   [4..8]   — bias_fnr (f32 LE)
    //   [8..12]  — bias_calibration_date (u32 LE)
    //   [12..16] — padding
    //   [16..48] — regime_hash full BLAKE3 ([u8;32], ADR-064 — was 8B partial)
    //   [48..80] — explanation_hash ([u8;32] from evidence.hash)
    //   [80..164] — zero

    pub fn set_bias(&mut self, fpr: f32, fnr: f32, calibration: u32) {
        self._reserved[0..4].copy_from_slice(&fpr.to_le_bytes());
        self._reserved[4..8].copy_from_slice(&fnr.to_le_bytes());
        self._reserved[8..12].copy_from_slice(&calibration.to_le_bytes());
    }

    /// Full 32-byte BLAKE3 policy hash (ADR-064). Zero until PolicyWatcher is live (ADR-064 debt).
    pub fn set_regime_hash_full(&mut self, hash: &[u8; 32]) {
        self._reserved[16..48].copy_from_slice(hash);
    }

    /// Deprecated: 8-byte partial regime_hash — birthday attack risk. Use set_regime_hash_full.
    #[deprecated(since = "3.2.0", note = "birthday attack risk — use set_regime_hash_full (ADR-064)")]
    pub fn set_regime_hash_partial(&mut self, hash_u64: u64) {
        self._reserved[16..24].copy_from_slice(&hash_u64.to_le_bytes());
    }

    /// Store BLAKE3(explanation_text) for off-chain appeal lookup.
    pub fn set_explanation_hash(&mut self, hash: &[u8; 32]) {
        self._reserved[48..80].copy_from_slice(hash);
    }

    /// Valida com chave de assinatura do operador.
    pub fn validate_with_key(&self, signing_key: &[u8]) -> bool {
        if self.entry_hash != self.calculate_hash() {
            return false;
        }
        let expected_vid = Self::compute_verdict_id(
            &self.entry_hash,
            self.ethical_verdict,
            self.entry_id,
            signing_key,
        );
        self.verdict_id == expected_vid
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
            verdict_id: [0; 32],
            _padding_verdict: [0; 5],
            previous_hash: [0; 32],
            entry_hash: [0; 32],
            merkle_root: [0; 32],
            protocol_version: 1,
            schema_version: 1,
            producer_id: [0; 32],
            _reserved: [0; 164],
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn finalize_produces_nonzero_verdict_id() {
        let mut entry = LedgerEntry {
            ethical_verdict: EthicalVerdict::Block,
            ..LedgerEntry::default()
        };
        entry.finalize();
        assert_ne!(entry.verdict_id, [0u8; 32]);
    }

    #[test]
    fn verdict_id_deterministic() {
        let mut a = LedgerEntry { ethical_verdict: EthicalVerdict::Report, ..LedgerEntry::default() };
        let mut b = LedgerEntry { ethical_verdict: EthicalVerdict::Report, ..LedgerEntry::default() };
        a.finalize();
        b.finalize();
        assert_eq!(a.verdict_id, b.verdict_id);
    }

    #[test]
    fn verdict_id_differs_by_verdict_type() {
        let mut allow = LedgerEntry { ethical_verdict: EthicalVerdict::Allow, ..LedgerEntry::default() };
        let mut block = LedgerEntry { ethical_verdict: EthicalVerdict::Block, ..LedgerEntry::default() };
        allow.finalize();
        block.finalize();
        assert_ne!(allow.verdict_id, block.verdict_id);
    }

    #[test]
    fn validate_passes_after_finalize() {
        let mut entry = LedgerEntry {
            ethical_verdict: EthicalVerdict::Allow,
            ..LedgerEntry::default()
        };
        entry.finalize();
        assert!(entry.validate());
    }

    #[test]
    fn validate_fails_after_tampering() {
        let mut entry = LedgerEntry::default();
        entry.finalize();
        entry.ethical_verdict = EthicalVerdict::Block;
        assert!(!entry.validate());
    }

    #[test]
    fn finalize_with_key_differs_from_zero_key() {
        let mut a = LedgerEntry::default();
        let mut b = LedgerEntry::default();
        a.finalize();
        b.finalize_with_key(b"operator-signing-key-production");
        assert_ne!(a.verdict_id, b.verdict_id);
    }

    #[test]
    fn size_is_384_bytes() {
        assert_eq!(size_of::<LedgerEntry>(), 384);
    }
}
