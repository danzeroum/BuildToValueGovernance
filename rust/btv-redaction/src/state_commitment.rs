//! Pedersen commitments para as estatísticas do ledger.
//!
//! Paper 3, §3.2: "state commitment vincula ambos os snapshots antes e depois."
//!
//! NOTA: enquanto a toolchain Noir nao estiver integrada (Semanas 18-30),
//! o commitment é implementado via BLAKE3 (computacionalmente binding).
//! O circuito Noir substituira isso por Pedersen em BabyJubJub.
use blake3::Hash;
use serde::{Deserialize, Serialize};

/// Pedersen commitment ao estado do ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCommitment {
    /// Ponto de commitment comprimido (32 bytes).
    /// Atualmente: BLAKE3(data). Em producao: Pedersen(fields, blinding) em BabyJubJub.
    pub commitment_point: [u8; 32],
    /// Timestamp do snapshot.
    pub timestamp: u64,
}

/// Par de commitments (antes, depois) vinculado pela prova ZK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionCommitmentPair {
    pub before: StateCommitment,
    pub after:  StateCommitment,
}

impl StateCommitment {
    pub fn from_statistics(stats: &super::group_stats::LedgerStatistics) -> Self {
        let data = stats.to_commitment_data();
        let hash: Hash = blake3::hash(&data);
        Self {
            commitment_point: *hash.as_bytes(),
            timestamp: stats.timestamp,
        }
    }

    /// Verifica que este commitment corresponde as estatisticas fornecidas.
    pub fn verify(&self, stats: &super::group_stats::LedgerStatistics) -> bool {
        let expected = Self::from_statistics(stats);
        self.commitment_point == expected.commitment_point
            && self.timestamp == expected.timestamp
    }
}
