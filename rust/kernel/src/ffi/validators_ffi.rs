// BuildToValue v2.0 - FFI Bridge for Validators
// Expõe validators Rust para Python via C ABI
//
// Architecture: Rust (validators) → C ABI → Python (ctypes/PyO3)
// DT-007: migrado de Validator (legado) para Module (canônico).
//
// Author: BuildToValue Architecture Team
// License: Apache 2.0

#![allow(clippy::duplicated_code)]
#![cfg(feature = "ffi-bindings")]

use crate::core::module::{Module, ScanContext};
use crate::validators::{
    ConsentValidator, ConsentRevocationValidator, SensitiveDataValidator,
    CpfValidator, CnpjValidator, CreditCardValidator,
};
use crate::evidence::Finding;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;

// ═══════════════════════════════════════════════════════════════════════════
// FFI STRUCTURES (C-compatible)
// ═══════════════════════════════════════════════════════════════════════════

#[repr(C)]
pub struct FFIFinding {
    pub rule_id:          *mut c_char,
    pub title:            *mut c_char,
    pub description:      *mut c_char,
    pub severity:         u8,
    pub confidence:       u8,
    pub validator_module: *mut c_char,
    pub metadata:         *mut c_char,
}

impl FFIFinding {
    fn from_finding(finding: &Finding) -> Self {
        let severity_value = finding.severity.to_u8();

        let bytes_to_cstring = |bytes: &[u8]| -> *mut c_char {
            let s = String::from_utf8_lossy(bytes)
                .trim_matches('\0')
                .to_string();
            CString::new(s).unwrap().into_raw()
        };

        Self {
            rule_id:          bytes_to_cstring(&finding.rule_id),
            title:            bytes_to_cstring(&finding.threat_category),
            description:      bytes_to_cstring(&finding.matched_text),
            severity:         severity_value,
            confidence:       finding.confidence,
            validator_module: CString::new(format!("{:?}", finding.module))
                .unwrap()
                .into_raw(),
            metadata: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct FFIValidationResult {
    pub findings:       *mut FFIFinding,
    pub findings_count: usize,
    pub error_message:  *mut c_char,
}

// ═══════════════════════════════════════════════════════════════════════════
// FFI EXPORTS - LGPD VALIDATORS
// ═══════════════════════════════════════════════════════════════════════════

/// Consent Validator (LGPD Art. 7º, I)
#[no_mangle]
pub unsafe extern "C" fn validate_consent(
    input: *const c_char,
    _metadata_json: *const c_char,
) -> FFIValidationResult {
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return ffi_error("Invalid UTF-8 input"),
    };
    let mut ctx = ScanContext::default();
    // Qualificado explicitamente para evitar ambiguidade com Iterator::scan
    convert_findings_to_ffi(Module::scan(&ConsentValidator::default(), input_str, &mut ctx))
}

/// Consent Revocation Validator (LGPD Art. 8º, § 5º)
#[no_mangle]
pub unsafe extern "C" fn validate_consent_revocation(
    input: *const c_char,
    _metadata_json: *const c_char,
) -> FFIValidationResult {
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return ffi_error("Invalid UTF-8 input"),
    };
    let mut ctx = ScanContext::default();
    convert_findings_to_ffi(Module::scan(&ConsentRevocationValidator::new(), input_str, &mut ctx))
}

/// Sensitive Data Validator (LGPD Art. 11)
#[no_mangle]
pub unsafe extern "C" fn validate_sensitive_data(
    input: *const c_char,
    _metadata_json: *const c_char,
) -> FFIValidationResult {
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return ffi_error("Invalid UTF-8 input"),
    };
    let mut ctx = ScanContext::default();
    convert_findings_to_ffi(Module::scan(&SensitiveDataValidator::default(), input_str, &mut ctx))
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn validate_batch(
    validator_names: *const c_char,
    inputs: *const *const c_char,
    inputs_count: usize,
    _metadata_json: *const c_char,
) -> FFIValidationResult {
    let validators_str = match CStr::from_ptr(validator_names).to_str() {
        Ok(s) => s,
        Err(_) => return ffi_error("Invalid validator names"),
    };

    let input_ptrs = slice::from_raw_parts(inputs, inputs_count);
    let mut all_findings: Vec<Finding> = Vec::new();

    for &input_ptr in input_ptrs {
        let input_str = match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut ctx = ScanContext::default();

        for validator_name in validators_str.split(',') {
            // Todas as chamadas qualificadas via Module::scan para evitar
            // ambiguidade com Iterator::scan no rust-analyzer.
            let findings: Vec<Finding> = match validator_name.trim() {
                "consent" =>
                    Module::scan(&ConsentValidator::default(), input_str, &mut ctx),
                "consent_revocation" =>
                    Module::scan(&ConsentRevocationValidator::new(), input_str, &mut ctx),
                "sensitive_data" =>
                    Module::scan(&SensitiveDataValidator::default(), input_str, &mut ctx),
                "cpf" =>
                    Module::scan(&CpfValidator::default(), input_str, &mut ctx),
                "cnpj" =>
                    Module::scan(&CnpjValidator::default(), input_str, &mut ctx),
                "credit_card" =>
                    Module::scan(&CreditCardValidator::default(), input_str, &mut ctx),
                _ => Vec::new(),
            };

            all_findings.extend(findings);
        }
    }

    convert_findings_to_ffi(all_findings)
}

// ═══════════════════════════════════════════════════════════════════════════
// MEMORY MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn free_validation_result(result: FFIValidationResult) {
    if !result.findings.is_null() {
        let findings_slice =
            slice::from_raw_parts_mut(result.findings, result.findings_count);

        for finding in findings_slice.iter_mut() {
            if !finding.rule_id.is_null()         { let _ = CString::from_raw(finding.rule_id); }
            if !finding.title.is_null()            { let _ = CString::from_raw(finding.title); }
            if !finding.description.is_null()      { let _ = CString::from_raw(finding.description); }
            if !finding.validator_module.is_null() { let _ = CString::from_raw(finding.validator_module); }
            if !finding.metadata.is_null()         { let _ = CString::from_raw(finding.metadata); }
        }

        let _ = Vec::from_raw_parts(
            result.findings,
            result.findings_count,
            result.findings_count,
        );
    }

    if !result.error_message.is_null() {
        let _ = CString::from_raw(result.error_message);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn ffi_error(msg: &str) -> FFIValidationResult {
    FFIValidationResult {
        findings:       std::ptr::null_mut(),
        findings_count: 0,
        error_message:  CString::new(msg).unwrap().into_raw(),
    }
}

fn convert_findings_to_ffi(findings: Vec<Finding>) -> FFIValidationResult {
    if findings.is_empty() {
        return FFIValidationResult {
            findings:       std::ptr::null_mut(),
            findings_count: 0,
            error_message:  std::ptr::null_mut(),
        };
    }

    let ffi_findings: Vec<FFIFinding> =
        findings.iter().map(FFIFinding::from_finding).collect();
    let findings_count = ffi_findings.len();
    let findings_ptr =
        Box::into_raw(ffi_findings.into_boxed_slice()) as *mut FFIFinding;

    FFIValidationResult {
        findings: findings_ptr,
        findings_count,
        error_message: std::ptr::null_mut(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_ffi_consent_validator_no_crash() {
        let input = CString::new("").unwrap();
        unsafe {
            let result = validate_consent(input.as_ptr(), std::ptr::null());
            free_validation_result(result);
        }
    }

    #[test]
    fn test_ffi_sensitive_data_health() {
        let input = CString::new("Paciente tem diagnóstico de diabetes").unwrap();
        unsafe {
            let result = validate_sensitive_data(input.as_ptr(), std::ptr::null());
            assert!(result.findings_count > 0, "HEALTH deve gerar finding");
            free_validation_result(result);
        }
    }

    #[test]
    fn test_ffi_error_message_freed() {
        let invalid: &[u8] = b"\xFF\xFE\x00";
        let input = invalid.as_ptr() as *const c_char;
        unsafe {
            let result = validate_consent(input, std::ptr::null());
            assert!(!result.error_message.is_null());
            free_validation_result(result);
        }
    }
}