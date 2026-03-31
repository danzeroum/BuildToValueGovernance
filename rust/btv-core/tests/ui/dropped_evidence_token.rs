// Case C: Silently dropping an EvidenceToken must trigger unused_must_use.
// Paper 1, Axiom 4.4: "weakening is prohibited" — silent drops are decision voids.
#![deny(unused_must_use)]
use btv_core::EvidenceToken;

fn main() {
    EvidenceToken::new(b"test context");
}
