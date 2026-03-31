//! Wrapper Rust → Noir verifier.
//!
//! Verificação é RAPIDA (~15ms): apenas a prova contra os public inputs,
//! sem witness. Status: stub até Semanas 24-28.

/// Verifier ZK para receipts de redação.
#[derive(Clone)]
pub struct RedactionVerifier {
    #[allow(dead_code)]
    verification_key: Vec<u8>,
}

impl RedactionVerifier {
    pub fn new(verification_key: Vec<u8>) -> Self {
        Self { verification_key }
    }

    /// Placeholder sem chave (para testes sem toolchain Noir).
    pub fn placeholder() -> Self {
        Self { verification_key: vec![] }
    }

    /// Verifica a prova ZK de um RedactionReceipt.
    ///
    /// - Se `proof_bytes` estiver vazio (modo direct), retorna `Ok(true)`.
    /// - Quando Noir integrado: chama `nargo verify` com proof + public_inputs.
    pub async fn verify(
        &self,
        receipt: &crate::redaction_receipt::RedactionReceipt,
    ) -> Result<bool, crate::protocol::RedactionError> {
        if receipt.proof_bytes.is_empty() {
            return Ok(true); // modo direct: consistencia verificada em protocol.rs
        }
        // TODO (Semanas 24-28): nargo verify
        Ok(false)
    }
}
