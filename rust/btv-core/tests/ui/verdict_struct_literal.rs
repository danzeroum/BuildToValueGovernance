// Case A: Struct-literal construction of Verdict must fail with E0451.
// Paper 1, Axiom 4.5(1): "all fields of Verdict are private."
use btv_core::Verdict;
use btv_types::Decision;

fn main() {
    let _v = Verdict {
        evidence_hash: todo!(),
        decision: Decision::Allow,
        explanation: String::new(),
        hmac_seal: [0u8; 32],
        jurisdiction: String::new(),
        policy_version: String::new(),
    };
}
