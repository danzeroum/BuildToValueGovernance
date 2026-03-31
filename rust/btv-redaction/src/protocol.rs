//! Protocolo de Accountable Redaction em 4 fases (Paper 3, §3.1–3.4).
use std::collections::HashSet;
use crate::{
    group_stats::{LedgerStatistics, RedactionEntry, field_from_u64},
    state_commitment::StateCommitment,
    authorized_redaction::AuthorizationVerifier,
    redaction_receipt::RedactionReceipt,
    verifier::RedactionVerifier,
};

/// Configuração do protocolo de redação.
#[derive(Debug, Clone)]
pub struct RedactionConfig {
    /// Tolerância ε: variação máxima permitida na taxa de aprovacao por grupo.
    pub epsilon: f64,
    pub max_batch_size: usize,
    pub protected_groups: Vec<String>,
    /// false = verificação direta (sem ZK); true = requer prova Noir.
    pub zk_enabled: bool,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            epsilon:           0.05,
            max_batch_size:    1000,
            protected_groups:  vec![
                "gender:female".into(), "gender:male".into(),
                "race:black".into(), "race:white".into(),
                "race:asian".into(), "race:hispanic".into(),
                "age_group:under_18".into(), "age_group:18_25".into(),
                "age_group:26_40".into(), "age_group:41_60".into(),
                "age_group:over_60".into(),
            ],
            zk_enabled: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RedactionError {
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),
    #[error("Batch too large: {count} exceeds max {max}")]
    BatchTooLarge { count: usize, max: usize },
    #[error("Empty batch: nothing to redact")]
    EmptyBatch,
    #[error("No protected groups affected")]
    NoProtectedGroupsAffected,
    #[error("ZK proving failed: {0}")]
    ProvingFailed(String),
    #[error("ZK proof invalid")]
    ProofInvalid,
    #[error("ε-consistency violated for group '{group}': delta={delta:.4}, epsilon={epsilon:.4}")]
    EpsilonViolation { group: String, delta: f64, epsilon: f64 },
}

/// Resultado de uma redação bem-sucedida.
pub struct RedactionResult {
    pub receipt:        RedactionReceipt,
    pub new_statistics: LedgerStatistics,
}

/// Motor de Accountable Redaction.
pub struct AccountableRedaction {
    config:   RedactionConfig,
    verifier: RedactionVerifier,
}

impl AccountableRedaction {
    pub fn new(config: RedactionConfig, verifier: RedactionVerifier) -> Self {
        Self { config, verifier }
    }

    /// Executa o protocolo completo de 4 fases.
    pub async fn execute(
        &self,
        current_stats: &LedgerStatistics,
        entries: Vec<RedactionEntry>,
        timestamp: u64,
    ) -> Result<RedactionResult, RedactionError> {
        if entries.is_empty() {
            return Err(RedactionError::EmptyBatch);
        }
        if entries.len() > self.config.max_batch_size {
            return Err(RedactionError::BatchTooLarge {
                count: entries.len(),
                max:   self.config.max_batch_size,
            });
        }

        // Phase 1: Authorization
        self.verify_authorization(&entries, timestamp)?;

        // Phase 2: State Commitment
        let simulated         = current_stats.simulate_redaction(&entries);
        let commitment_before = StateCommitment::from_statistics(current_stats);
        let commitment_after  = StateCommitment::from_statistics(&simulated);

        // Phase 3: ZK / Direct consistency check
        let (proof_bytes, public_inputs) = if self.config.zk_enabled {
            self.prove_consistency(&commitment_before, &commitment_after,
                                   current_stats, &simulated)?;
            (vec![], self.public_inputs(&commitment_before, &commitment_after))
        } else {
            self.verify_consistency_direct(current_stats, &simulated)?;
            (vec![], self.public_inputs(&commitment_before, &commitment_after))
        };

        // Phase 4: Build receipt
        let affected_groups: Vec<String> = entries.iter()
            .map(|e| e.group_label.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let receipt = RedactionReceipt {
            batch_id:            format!("redact-{timestamp}"),
            entries_count:       entries.len(),
            commitment_before,
            commitment_after,
            epsilon:             self.config.epsilon,
            affected_groups,
            proof_bytes,
            public_inputs,
            timestamp,
            authority_signature: [0; 64],
            authority_pubkey:    [0; 32],
        };

        Ok(RedactionResult { receipt, new_statistics: simulated })
    }

    fn verify_authorization(
        &self,
        entries: &[RedactionEntry],
        timestamp: u64,
    ) -> Result<(), RedactionError> {
        let labels: Vec<&str> = entries.iter().map(|e| e.group_label.as_str()).collect();
        AuthorizationVerifier::verify_batch(entries, &labels, timestamp)
            .map_err(|e| RedactionError::AuthorizationFailed(e.to_string()))
    }

    fn verify_consistency_direct(
        &self,
        before: &LedgerStatistics,
        after:  &LedgerStatistics,
    ) -> Result<(), RedactionError> {
        for group in &self.config.protected_groups {
            let rate_before = before.get_group(group).map(|g| g.approval_rate()).unwrap_or(0.0);
            let rate_after  = after .get_group(group).map(|g| g.approval_rate()).unwrap_or(0.0);
            let delta = (rate_before - rate_after).abs();
            if delta > self.config.epsilon {
                return Err(RedactionError::EpsilonViolation {
                    group:   group.clone(),
                    delta,
                    epsilon: self.config.epsilon,
                });
            }
        }
        Ok(())
    }

    fn prove_consistency(
        &self,
        _before: &StateCommitment,
        _after:  &StateCommitment,
        stats_before: &LedgerStatistics,
        stats_after:  &LedgerStatistics,
    ) -> Result<(), RedactionError> {
        // TODO (Semanas 18-30): chamar nargo prove
        // Por ora, fallback para verificação direta
        self.verify_consistency_direct(stats_before, stats_after)
    }

    fn public_inputs(
        &self,
        before: &StateCommitment,
        after:  &StateCommitment,
    ) -> Vec<[u8; 32]> {
        vec![
            before.commitment_point,
            after.commitment_point,
            field_from_u64(self.config.epsilon.to_bits()),
            field_from_u64(self.config.protected_groups.len() as u64),
        ]
    }
}
