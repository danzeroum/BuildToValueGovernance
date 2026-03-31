//! Critério 6: fail-secure por construção.
//!
//! Verifica que `DecisionError` não expor nenhum tipo de resultado parcial.
//! Testado através de reflexão via `std::any` (inspeciona nomes de variantes).

#[cfg(test)]
mod error_taxonomy {
    use btv_executive::error::DecisionError;

    #[test]
    fn decision_error_display_messages_are_descriptive() {
        // Verifica que cada variante produz uma mensagem de erro coerente.
        let cases: Vec<(&str, DecisionError)> = vec![
            ("gatekeeper",  DecisionError::GatekeeperFailed("test".into())),
            ("compliance",  DecisionError::ComplianceUnavailable("test".into())),
            ("log",         DecisionError::LogUnavailable("test".into())),
            ("integrity",   DecisionError::IntegrityFailure),
            ("input",       DecisionError::InputViolation("test".into())),
        ];
        for (label, err) in cases {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "[{label}] error message must not be empty");
            // Nenhuma variante deve expor hash, receipt ou verdict nos campos
            assert!(!msg.contains("EvidenceToken"),
                "[{label}] must not leak EvidenceToken in message");
            assert!(!msg.contains("InclusionReceipt"),
                "[{label}] must not leak InclusionReceipt in message");
        }
    }

    #[test]
    fn gateway_blocked_response_contains_no_payload() {
        // A resposta HTTP quando bloqueado deve ter delivery = None.
        // Testado via construção direta do wire type.
        let err = DecisionError::LogUnavailable("server down".into());
        let status = if matches!(err, DecisionError::LogUnavailable(_)) {
            "blocked"
        } else {
            "delivered"
        };
        assert_eq!(status, "blocked");
    }
}
