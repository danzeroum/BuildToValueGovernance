// Clone attempt: EvidenceToken does not implement Clone — must fail with E0599.
// Paper 1, Axiom 4.4: "contraction is prohibited."
use btv_core::EvidenceToken;

fn main() {
    let token = EvidenceToken::new(b"test context");
    let _cloned = token.clone();
}
