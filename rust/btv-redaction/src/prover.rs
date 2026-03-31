//! Wrapper Rust → Noir prover.
//!
//! Status: stub. Integração completa na Fase 5 (Semanas 20-28).
//! Quando integrado, chamara `nargo prove` via subprocess e retornara os bytes da prova.

/// Prover ZK para o circuito `statistical_consistency`.
pub struct RedactionProver {
    #[allow(dead_code)]
    circuit_path: std::path::PathBuf,
}

impl RedactionProver {
    pub fn new(circuit_path: std::path::PathBuf) -> Self {
        Self { circuit_path }
    }

    /// Gera uma prova ZK para o batch.
    ///
    /// Returns `(proof_bytes, public_inputs)`.
    /// Tempo estimado: ~2.1s por batch de 1000 (Barretenberg/Groth16).
    pub async fn prove(
        &self,
        _stats_before: &crate::group_stats::LedgerStatistics,
        _stats_after:  &crate::group_stats::LedgerStatistics,
        _epsilon: f64,
    ) -> Result<(Vec<u8>, Vec<[u8; 32]>), crate::protocol::RedactionError> {
        // TODO (Semanas 20-28):
        // 1. Escrever witness em Prover.toml
        // 2. Executar `nargo prove --package statistical_consistency`
        // 3. Ler prova de target/proofs/statistical_consistency/
        // 4. Retornar (proof_bytes, public_inputs)
        Err(crate::protocol::RedactionError::ProvingFailed(
            "Noir prover not yet integrated (Fase 5, Semanas 20-28)".into()
        ))
    }
}
