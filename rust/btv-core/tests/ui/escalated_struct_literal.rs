// Escalated Case A: Struct-literal construction of EscalatedVerdict must fail E0451.
// Corollary 4.8: same private-field protection as Verdict.
use btv_core::EscalatedVerdict;

fn main() {
    let _v = EscalatedVerdict {
        operator_id: "admin".to_string(),
        reason: "timeout".to_string(),
        hmac_seal: [0u8; 32],
    };
}
