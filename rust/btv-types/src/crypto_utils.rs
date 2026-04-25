//! Shared cryptographic utilities for BuildToValue constitutional types.
//!
//! Centralized here to avoid duplication between btv-core (HMAC creation) and
//! btv-judicial (HMAC verification). Both crates already depend on btv-types,
//! so adding this here violates no constitutional separation.
//!
//! v2.3.1: Extracted from btv-core/src/hmac.rs and btv-judicial/src/hmac_verify.rs.

/// Constant-time comparison of two 32-byte arrays.
///
/// Prevents timing side-channel attacks by always comparing ALL bytes before
/// returning the result, regardless of where they differ. Returns false if
/// any byte differs.
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_arrays_pass() {
        let a = [42u8; 32];
        assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn different_arrays_fail() {
        let a = [1u8; 32];
        let mut b = [1u8; 32];
        b[15] = 0xFF;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn zero_arrays_pass() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn single_bit_difference_fails() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 0x01;
        assert!(!constant_time_eq(&a, &b));
    }
}
