//! Receipt criptográfico provando que um batch de redacões foi
//! executado com verificação de consistência ε-estatística.
//!
//! Este receipt é persistido em btv-sigma e verificado pelo btv-judicial.
use serde::{Deserialize, Serialize};

/// Receipt de uma redação accountable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionReceipt {
    pub batch_id:           String,
    pub entries_count:      usize,
    pub commitment_before:  super::state_commitment::StateCommitment,
    pub commitment_after:   super::state_commitment::StateCommitment,
    pub epsilon:            f64,
    pub affected_groups:    Vec<String>,
    /// Bytes da prova ZK (~3.2kB Barretenberg; vazio no modo direct).
    pub proof_bytes:        Vec<u8>,
    pub public_inputs:      Vec<[u8; 32]>,
    pub timestamp:          u64,
    #[serde(with = "btv_types::serde_bytes_64_pub")]
    pub authority_signature: [u8; 64],
    pub authority_pubkey:   [u8; 32],
}

impl RedactionReceipt {
    /// Converte para o wire format de btv-types (para persistencia em btv-sigma).
    pub fn to_wire(&self) -> btv_types::RedactionReceiptWire {
        btv_types::RedactionReceiptWire {
            batch_id:            self.batch_id.clone(),
            entries_count:       self.entries_count,
            commitment_before:   self.commitment_before.commitment_point,
            commitment_after:    self.commitment_after.commitment_point,
            epsilon:             self.epsilon,
            affected_groups:     self.affected_groups.clone(),
            proof_bytes:         self.proof_bytes.clone(),
            public_inputs:       self.public_inputs.clone(),
            timestamp:           self.timestamp,
            authority_signature: self.authority_signature,
            authority_pubkey:    self.authority_pubkey,
        }
    }
}
