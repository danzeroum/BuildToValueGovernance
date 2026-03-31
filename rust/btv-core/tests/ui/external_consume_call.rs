// Case B: Calling pub(crate) method from outside the crate must fail with E0624.
// Paper 1, Axiom 4.5(2): "EvidenceToken::consume is pub(crate)."
use btv_core::EvidenceToken;

fn main() {
    let token = EvidenceToken::new(b"test context");
    let _hash = token.consume();
}
