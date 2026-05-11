//! Module trait tests
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::gatekeeper::Gatekeeper;

    #[test]
    fn gatekeeper_implements_default() {
        let _gk = Gatekeeper::default();
    }

    #[test]
    fn gatekeeper_new_and_default_equivalent() {
        let gk1 = Gatekeeper::new();
        let gk2 = Gatekeeper::default();
        // Both should behave identically
        assert_eq!(
            gk1.adapt(b"test").is_ok(),
            gk2.adapt(b"test").is_ok()
        );
    }
}
