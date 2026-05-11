//! Bias declaration mandate tests (ADR-039)
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::gatekeeper::Gatekeeper;

    #[test]
    fn evidence_has_bias_declaration() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"bias test input").unwrap();
        // BiasDeclaration must be present on every TechnicalEvidence
        let _bias = &ev.bias_declaration;
    }

    #[test]
    fn bias_declaration_has_model_id() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"model id test").unwrap();
        assert!(!ev.bias_declaration.model_id.is_empty());
    }

    #[test]
    fn bias_declaration_training_cutoff_nonzero() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"training cutoff").unwrap();
        assert!(ev.bias_declaration.training_cutoff_unix > 0);
    }

    #[test]
    fn bias_declaration_known_biases_accessible() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"known biases").unwrap();
        // known_biases may be empty but must not panic on access
        let _biases = &ev.bias_declaration.known_biases;
    }

    #[test]
    fn bias_declaration_confidence_score_in_range() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"confidence test").unwrap();
        assert!(ev.bias_declaration.confidence_score >= 0.0);
        assert!(ev.bias_declaration.confidence_score <= 1.0);
    }

    #[test]
    fn two_different_inputs_have_same_model_id() {
        let gk = Gatekeeper::new();
        let ev1 = gk.adapt(b"first").unwrap();
        let ev2 = gk.adapt(b"second").unwrap();
        // model_id is static per Gatekeeper instance
        assert_eq!(ev1.bias_declaration.model_id, ev2.bias_declaration.model_id);
    }

    #[test]
    fn bias_declaration_preserved_after_finalize() {
        let mut ev = buildtovalue_kernel::evidence::TechnicalEvidence::new(99);
        let original_model_id = ev.bias_declaration.model_id.clone();
        ev.finalize().unwrap();
        assert_eq!(ev.bias_declaration.model_id, original_model_id);
    }
}
