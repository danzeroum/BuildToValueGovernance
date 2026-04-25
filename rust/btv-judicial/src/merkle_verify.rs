//! Verificação de inclusão Merkle.
//!
//! Para proofs emitidos por btv-sigma use `verify_side_proof` + `ProofSide`
//! (ordem posicional estrita Side::Left / Side::Right).
//! `verify_merkle_inclusion` (ordem canônica min-first) é mantido apenas
//! para formatos legados.

/// Re-exporta verificação posicional (btv-sigma) e API legada de `btv-types`.
pub use btv_types::merkle_verify::{verify_side_proof, ProofSide};
pub use btv_types::verify_merkle_inclusion;

/// Verifica consistência do root: receipt.merkle_root == log_root.
///
/// Se o Executivo retornar um root diferente do que o Judiciário buscou
/// diretamente em btv-sigma, houve falsificação.
pub fn verify_root_consistency(
    receipt: &btv_types::InclusionReceiptWire,
    log_root: &[u8; 32],
) -> bool {
    &receipt.merkle_root == log_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use btv_types::{InclusionReceiptWire, MerkleProof};

    #[test]
    fn root_consistency_pass() {
        let root = [0xABu8; 32];
        let receipt = InclusionReceiptWire {
            log_index: 0, merkle_root: root,
            signature: [0u8; 64], timestamp: 0,
        };
        assert!(verify_root_consistency(&receipt, &root));
    }

    #[test]
    fn root_consistency_fail() {
        let root = [0xABu8; 32];
        let different = [0xCDu8; 32];
        let receipt = InclusionReceiptWire {
            log_index: 0, merkle_root: different,
            signature: [0u8; 64], timestamp: 0,
        };
        assert!(!verify_root_consistency(&receipt, &root));
    }
}
