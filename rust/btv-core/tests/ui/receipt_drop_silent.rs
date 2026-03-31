// receipt_drop_silent.rs
//
// Verifica que campos privados de InclusionReceipt nao podem ser acessados
// externamente — mesma familia de invariante que delivery_struct_literal.rs
// mas para o tipo Receipt (Axiom II, Paper 2).
//
// Esta familia de testes (compile_fail glob) exige que TODOS os .rs
// do diretorio falhem em compilar. Este arquivo falha com E0451.

use btv_core::InclusionReceipt;

fn main() {
    // InclusionReceipt tem campos pub(crate) -- struct literal externo falha.
    let _r = InclusionReceipt {
        log_index:   0u64,
        merkle_root: [0u8; 32],
        signature:   [0u8; 64],
        timestamp:   0u64,
    };
}
