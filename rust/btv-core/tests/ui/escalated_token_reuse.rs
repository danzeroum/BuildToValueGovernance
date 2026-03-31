// Escalated Case B: Reusing an OperatorToken after move must fail with E0382.
// Corollary 4.8: linearity — once consumed, cannot be used again.
use btv_core::{OperatorToken, EscalatedVerdict};

fn main() {
    let token = OperatorToken::new("admin".to_string());
    let _v1 = EscalatedVerdict::new(token, "reason1".to_string());
    // `token` was moved — reuse must fail E0382
    let _v2 = EscalatedVerdict::new(token, "reason2".to_string());
}
