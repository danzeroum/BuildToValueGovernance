//! Orquestrador de verificação completa de DeliveryPayload.
//!
//! Verifica HMAC + Ed25519 + Merkle + root consistency em sequência.
//! Se QUALQUER verificação falhar → overall_valid = false (fail-secure).
use crate::{HmacVerifier, ReceiptVerifier};
use crate::merkle_verify::{verify_merkle_inclusion, verify_root_consistency};

/// Resultado de verificação de um DeliveryPayload.
#[derive(Debug, Clone)]
pub struct PayloadVerification {
    pub hmac_valid:      bool,
    pub signature_valid: bool,
    pub merkle_valid:    bool,
    pub root_consistent: bool,
    pub overall_valid:   bool,
    pub verdict_hash:    [u8; 32],
    pub details:         String,
}

/// Verifica todas as garantias criptográficas de um DeliveryPayload.
///
/// Checks (em ordem de precedência):
/// 1. HMAC seal no VerdictRecord (Paper 1, §3.2)
/// 2. Ed25519 no InclusionReceiptWire (Paper 2, Case D)
/// 3. Root consistency (receipt.root == log root)
/// 4. Merkle inclusion proof
pub fn verify_payload(
    payload:          &btv_types::DeliveryPayload,
    hmac_verifier:    &HmacVerifier,
    receipt_verifier: &ReceiptVerifier,
    proof:            &btv_types::MerkleProof,
    log_root:         &[u8; 32],
) -> PayloadVerification {
    let verdict_hash = payload.verdict.evidence_hash.0;

    let hmac_valid      = hmac_verifier.verify(&payload.verdict).unwrap_or(false);
    let signature_valid = receipt_verifier.verify(&payload.receipt, &verdict_hash).unwrap_or(false);
    let root_consistent = verify_root_consistency(&payload.receipt, log_root);
    let merkle_valid    = verify_merkle_inclusion(log_root, &verdict_hash, proof);

    let overall_valid = hmac_valid && signature_valid && merkle_valid && root_consistent;

    let details = if overall_valid {
        "All cryptographic checks passed.".into()
    } else {
        let mut reasons = Vec::new();
        if !hmac_valid      { reasons.push("HMAC seal invalid"); }
        if !signature_valid { reasons.push("Ed25519 signature invalid"); }
        if !root_consistent { reasons.push("Receipt root != log root"); }
        if !merkle_valid    { reasons.push("Merkle proof invalid"); }
        format!("Verification FAILED: {}", reasons.join("; "))
    };

    PayloadVerification {
        hmac_valid, signature_valid, merkle_valid,
        root_consistent, overall_valid, verdict_hash, details,
    }
}
