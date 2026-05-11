//! Rescan / re-evaluation tests
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::gatekeeper::Gatekeeper;

    #[test]
    fn rescan_same_input_same_hash() {
        let gk = Gatekeeper::new();
        let ev1 = gk.adapt(b"rescan test input").unwrap();
        let ev2 = gk.adapt(b"rescan test input").unwrap();
        assert_eq!(ev1.content_hash_blake3, ev2.content_hash_blake3);
    }

    #[test]
    fn rescan_different_input_different_hash() {
        let gk = Gatekeeper::new();
        let ev1 = gk.adapt(b"first").unwrap();
        let ev2 = gk.adapt(b"second").unwrap();
        assert_ne!(ev1.content_hash_blake3, ev2.content_hash_blake3);
    }

    #[test]
    fn rescan_risk_score_deterministic() {
        let gk = Gatekeeper::new();
        let ev1 = gk.adapt(b"deterministic risk").unwrap();
        let ev2 = gk.adapt(b"deterministic risk").unwrap();
        assert_eq!(
            (ev1.composite_risk_score * 1000.0) as u64,
            (ev2.composite_risk_score * 1000.0) as u64
        );
    }
}
