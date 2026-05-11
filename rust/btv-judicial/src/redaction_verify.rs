//! Verificação de ZK receipts de redação (Paper 3).
//!
//! Integração completa com btv-redaction será feita nas Semanas 24-28.
//! Por ora, verifica receipts no modo direct (proof_bytes vazio).
use crate::hmac_verify::JudicialError;

/// Verifica um RedactionReceiptWire.
///
/// - proof_bytes vazio: modo direct — a consistência foi verificada em btv-redaction
///   sem ZK; o Judiciário aceita e registra.
/// - proof_bytes preenchido: quando Noir integrado, verificará a prova ZK.
pub fn verify_redaction_receipt(
    receipt: &btv_types::RedactionReceiptWire,
) -> Result<bool, JudicialError> {
    if receipt.epsilon < 0.0 || receipt.epsilon > 1.0 {
        return Err(JudicialError::VerificationFailed(
            format!("epsilon {} out of range [0,1]", receipt.epsilon)
        ));
    }
    if receipt.affected_groups.is_empty() {
        return Err(JudicialError::VerificationFailed(
            "No affected groups in redaction receipt".into()
        ));
    }

    if receipt.proof_bytes.is_empty() {
        return Ok(true);
    }

    // TODO (Semanas 24-28): integrar noir_rs verifier
    Err(JudicialError::VerificationFailed(
        "ZK verification not yet integrated (Fase 5, Semanas 24-28)".into()
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_receipt(proof_bytes: Vec<u8>) -> btv_types::RedactionReceiptWire {
        btv_types::RedactionReceiptWire {
            batch_id:            "batch-test".into(),
            entries_count:       5,
            commitment_before:   [0u8; 32],
            commitment_after:    [1u8; 32],
            epsilon:             0.05,
            affected_groups:     vec!["gender:female".into()],
            proof_bytes,
            public_inputs:       vec![],
            timestamp:           1_700_000_000,
            authority_signature: [0u8; 64],
            authority_pubkey:    [0u8; 32],
        }
    }

    #[test]
    fn direct_mode_accepted() {
        let receipt = make_receipt(vec![]);
        assert!(verify_redaction_receipt(&receipt).unwrap());
    }

    #[test]
    fn invalid_epsilon_rejected() {
        let mut receipt = make_receipt(vec![]);
        receipt.epsilon = 1.5;
        assert!(verify_redaction_receipt(&receipt).is_err());
    }

    #[test]
    fn empty_groups_rejected() {
        let mut receipt = make_receipt(vec![]);
        receipt.affected_groups = vec![];
        assert!(verify_redaction_receipt(&receipt).is_err());
    }
}
