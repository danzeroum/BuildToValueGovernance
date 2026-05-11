//! Gatekeeper pipeline tests
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::gatekeeper::Gatekeeper;

    #[test]
    fn empty_input_blocked() {
        let gk = Gatekeeper::new();
        assert!(gk.adapt(b"").is_err());
    }

    #[test]
    fn oversized_input_blocked() {
        let gk = Gatekeeper::new();
        let big = vec![0x41u8; 65 * 1024];
        assert!(gk.adapt(&big).is_err());
    }

    #[test]
    fn valid_input_passes_gatekeeper() {
        let gk = Gatekeeper::new();
        let result = gk.adapt(b"valid safe input");
        assert!(result.is_ok());
    }

    #[test]
    fn gatekeeper_produces_evidence() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"produce evidence").unwrap();
        assert!(ev.timestamp_unix > 0);
        assert_ne!(ev.content_hash_blake3, [0u8; 32]);
    }

    #[test]
    fn gatekeeper_evidence_size_invariant() {
        use std::mem::size_of;
        use buildtovalue_kernel::core::types::EVIDENCE_SIZE;
        assert_eq!(size_of::<buildtovalue_kernel::evidence::TechnicalEvidence>(), EVIDENCE_SIZE);
    }

    #[test]
    fn gatekeeper_blocks_then_passes() {
        let gk = Gatekeeper::new();
        assert!(gk.adapt(b"").is_err());
        assert!(gk.adapt(b"valid input").is_ok());
        assert!(gk.adapt(b"").is_err());
    }

    #[test]
    fn multiple_valid_inputs_all_pass() {
        let gk = Gatekeeper::new();
        for i in 0..10u8 {
            let input = format!("valid input number {i}");
            assert!(gk.adapt(input.as_bytes()).is_ok());
        }
    }
}
