// Escalated Case C: Calling pub(crate) OperatorToken::consume externally must fail E0624.
// Corollary 4.8: same protection as EvidenceToken::consume.
use btv_core::OperatorToken;

fn main() {
    let token = OperatorToken::new("admin".to_string());
    let _ = token.consume();
}
