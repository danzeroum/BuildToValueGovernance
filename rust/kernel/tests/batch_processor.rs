//! Batch processor tests
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::gatekeeper::Gatekeeper;

    #[test]
    fn batch_empty_input_blocked() {
        let gk = Gatekeeper::new();
        let result = gk.adapt(b"");
        assert!(result.is_err());
    }

    #[test]
    fn batch_oversized_blocked() {
        let gk = Gatekeeper::new();
        let big = vec![0x41u8; 65 * 1024];
        let result = gk.adapt(&big);
        assert!(result.is_err());
    }

    #[test]
    fn batch_valid_input_passes() {
        let gk = Gatekeeper::new();
        let result = gk.adapt(b"hello world");
        assert!(result.is_ok());
    }

    #[test]
    fn batch_multiple_valid_inputs() {
        let gk = Gatekeeper::new();
        let inputs: Vec<&[u8]> = vec![
            b"first input",
            b"second input",
            b"third input",
        ];
        for input in inputs {
            assert!(gk.adapt(input).is_ok());
        }
    }

    #[test]
    fn batch_null_bytes_handled() {
        let gk = Gatekeeper::new();
        let result = gk.adapt(b"hello\x00world");
        // null bytes are valid input -- gatekeeper should handle them
        let _ = result; // either ok or err is acceptable, must not panic
    }

    #[test]
    fn batch_unicode_input_passes() {
        let gk = Gatekeeper::new();
        let result = gk.adapt("Ola mundo com acentos".as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn batch_binary_data_handled() {
        let gk = Gatekeeper::new();
        let binary = vec![0xFFu8; 100];
        let result = gk.adapt(&binary);
        // binary data: either ok or err, must not panic
        let _ = result;
    }

    #[test]
    fn batch_exactly_at_limit_passes() {
        let gk = Gatekeeper::new();
        let at_limit = vec![0x41u8; 64 * 1024];
        let result = gk.adapt(&at_limit);
        assert!(result.is_ok());
    }

    #[test]
    fn batch_one_over_limit_blocked() {
        let gk = Gatekeeper::new();
        let over = vec![0x41u8; 64 * 1024 + 1];
        let result = gk.adapt(&over);
        assert!(result.is_err());
    }
}
