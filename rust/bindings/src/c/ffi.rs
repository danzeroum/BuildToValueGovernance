//! C Foreign Function Interface — Phase 3 (fail-secure, real kernel).
//!
//! Phase 3 Changes:
//! - process_evidence_real() calls buildtovalue_kernel::Gatekeeper (not stub)
//! - No more hardcoded risk=42 or audit_trail_id=123456789
//! - Input validation: max 10MB, non-empty, valid UTF-8
//! - Fail-secure: any error → return code -3, never panic
//!
//! # Safety
//! All functions receiving raw pointers are `unsafe` and require
//! non-null, valid pointers for the declared lengths.

use std::slice;
use std::time;
use super::TechnicalEvidence;

const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Scans input for technical evidence using the real kernel Gatekeeper.
///
/// # Safety
/// - `input_ptr` must point to a valid buffer of at least `input_len` bytes
/// - `output_ptr` must point to a valid writable `TechnicalEvidence`
///
/// # Returns
/// - `0`  success
/// - `-1` null pointer
/// - `-2` invalid input (empty, too large, invalid UTF-8)
/// - `-3` processing error (logged, fail-secure)
#[no_mangle]
pub unsafe extern "C" fn btv_scan_for_evidence(
    input_ptr: *const u8,
    input_len: usize,
    output_ptr: *mut TechnicalEvidence,
) -> i32 {
    if input_ptr.is_null() || output_ptr.is_null() {
        log::error!("btv_scan_for_evidence: null pointer");
        return -1;
    }
    if input_len == 0 || input_len > MAX_INPUT_SIZE {
        log::error!("btv_scan_for_evidence: invalid input_len={input_len}");
        return -2;
    }

    let input_slice = slice::from_raw_parts(input_ptr, input_len);
    let input_str = match std::str::from_utf8(input_slice) {
        Ok(s) => s,
        Err(e) => {
            log::error!("btv_scan_for_evidence: invalid UTF-8: {e}");
            return -2;
        }
    };

    match process_evidence_real(input_str) {
        Ok(ev) => { *output_ptr = ev; 0 }
        Err(e) => {
            log::error!("btv_scan_for_evidence: processing error: {e}");
            -3
        }
    }
}

/// C API version.
#[no_mangle]
pub extern "C" fn btv_api_version() -> u32 {
    super::C_API_VERSION
}

/// Initialize (no-op; Gatekeeper is stateless).
#[no_mangle]
pub extern "C" fn btv_initialize() -> i32 {
    log::info!("btv_initialize: C FFI v{}", super::C_API_VERSION);
    0
}

/// Cleanup (no-op).
#[no_mangle]
pub extern "C" fn btv_cleanup() {}

fn process_evidence_real(input: &str) -> Result<TechnicalEvidence, String> {
    use buildtovalue_kernel::{Gatekeeper, RiskLevel};
    use uuid::Uuid;

    let start = time::Instant::now();
    let audit_trail_id = Uuid::new_v4().as_u128();

    let mut gatekeeper = Gatekeeper::new();
    let ev = gatekeeper.scan_for_evidence(input, audit_trail_id);
    let elapsed_us = start.elapsed().as_micros() as u64;

    let risk_level_u8 = match ev.risk_level {
        RiskLevel::Safe     => 0u8,
        RiskLevel::Low      => 1,
        RiskLevel::Medium   => 2,
        RiskLevel::High     => 3,
        RiskLevel::Critical => 4,
    };

    Ok(TechnicalEvidence {
        protocol_version: 2,
        audit_trail_id,
        timestamp: ev.timestamp as u64,
        evidence_hash: ev.hash,
        composite_risk: (ev.composite_risk * 255.0) as u8,
        risk_level: risk_level_u8,
        finding_count: ev.finding_count,
        critical_count: ev.critical_count,
        input_size: ev.input_size as usize,
        processing_time_us: elapsed_us,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_evidence_real_returns_real_data() {
        let ev = process_evidence_real("test input").unwrap();
        assert_ne!(ev.audit_trail_id, 123456789, "STUB: hardcoded audit_trail_id");
        assert_ne!(ev.composite_risk, 42, "STUB: hardcoded risk=42");
        assert_eq!(ev.protocol_version, 2);
        assert!(ev.processing_time_us > 0);
        assert!(ev.input_size > 0);
    }

    #[test]
    fn null_pointers_return_error() {
        unsafe {
            let mut output = TechnicalEvidence::default();
            assert_eq!(btv_scan_for_evidence(std::ptr::null(), 10, &mut output), -1);
        }
    }

    #[test]
    fn empty_input_returns_error() {
        unsafe {
            let byte = 0u8;
            let mut output = TechnicalEvidence::default();
            assert_eq!(btv_scan_for_evidence(&byte, 0, &mut output), -2);
        }
    }

    #[test]
    fn api_version_is_2() {
        assert_eq!(btv_api_version(), 2);
    }
}
