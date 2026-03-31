//! Estatísticas por grupo protegido — witness do circuito ZK.
//!
//! Os valores aqui são os que o circuito Noir confirma via Pedersen commitment.
//! Nenhum dado real de grupo é revelado na prova (apenas os commitments são públicos).
use serde::{Deserialize, Serialize};

/// Estatísticas de um grupo protegido.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStats {
    pub group_label: String,
    pub total:       u64,
    pub approved:    u64,
    pub denied:      u64,
    pub redacted:    u64,
}

impl GroupStats {
    /// Taxa de aprovacao: approved / total. Retorna 0.0 se total == 0.
    pub fn approval_rate(&self) -> f64 {
        if self.total == 0 { return 0.0; }
        self.approved as f64 / self.total as f64
    }

    /// Serializa para elementos de campo (fixed-point, big-endian 32 bytes).
    pub fn to_field_elements(&self) -> [([u8; 32], [u8; 32], [u8; 32], [u8; 32]); 1] {
        [(
            field_from_u64(self.total),
            field_from_u64(self.approved),
            field_from_u64(self.denied),
            field_from_u64(self.redacted),
        )]
    }
}

/// Estatísticas agregadas de todos os grupos em um instante.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerStatistics {
    pub groups:          Vec<GroupStats>,
    pub total_decisions: u64,
    pub timestamp:       u64,
}

impl LedgerStatistics {
    pub fn get_group(&self, label: &str) -> Option<&GroupStats> {
        self.groups.iter().find(|g| g.group_label == label)
    }

    /// Simula a remocao de entradas e computa novas estatisticas (witness ZK).
    pub fn simulate_redaction(
        &self,
        entries: &[RedactionEntry],
    ) -> LedgerStatistics {
        let mut new_groups = self.groups.clone();
        let mut new_total  = self.total_decisions;

        for entry in entries {
            if let Some(g) = new_groups.iter_mut()
                .find(|g| g.group_label == entry.group_label)
            {
                g.total    = g.total.saturating_sub(1);
                if entry.was_approved {
                    g.approved = g.approved.saturating_sub(1);
                } else {
                    g.denied = g.denied.saturating_sub(1);
                }
                g.redacted += 1;
            }
            new_total = new_total.saturating_sub(1);
        }

        LedgerStatistics { groups: new_groups, total_decisions: new_total, timestamp: self.timestamp }
    }

    /// Serializa todos os grupos para o Pedersen commitment.
    pub fn to_commitment_data(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.total_decisions.to_le_bytes());
        for g in &self.groups {
            buf.extend_from_slice(g.group_label.as_bytes());
            buf.push(0); // null separator
            buf.extend_from_slice(&g.total.to_le_bytes());
            buf.extend_from_slice(&g.approved.to_le_bytes());
            buf.extend_from_slice(&g.denied.to_le_bytes());
        }
        buf
    }
}

/// Uma entrada alvo de redacao.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionEntry {
    pub verdict_hash:      [u8; 32],
    pub group_label:       String,
    pub was_approved:      bool,
    /// Assinatura Ed25519 do titular dos dados autorizando a remocao (Paper 3, Phase 1).
    #[serde(with = "btv_types::serde_bytes_64_pub")]
    pub subject_signature: [u8; 64],
    pub subject_pubkey:    [u8; 32],
}

/// Converte u64 para elemento de campo (32 bytes, big-endian, zero-padded).
pub fn field_from_u64(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}
