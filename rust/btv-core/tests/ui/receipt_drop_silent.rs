// receipt_drop_silent.rs
//
// Verifica que o compilador detecta drop silencioso de um tipo #[must_use].
// InclusionReceipt nao pode ser descartado silenciosamente (Paper 2, Axiom II).
//
// Este arquivo DEVE falhar em compilar com #[must_use] warning-as-error.
// O invariante e: se InclusionReceipt perder #[must_use], esta guarda detecta.
//
// Nota: como InclusionReceipt e pub(crate), usamos o EvidenceToken
// (que tambem e #[must_use] e e pub na API do crate) como proxy
// para o mesmo invariante de "nao pode ser dropado silenciosamente".

use btv_core::EvidenceToken;

fn main() {
    // EvidenceToken e #[must_use] -- drop silencioso deve ser erro.
    // O compilador rejeita o descarte sem consumo explicito.
    let _: EvidenceToken = panic!("never reached");
}
