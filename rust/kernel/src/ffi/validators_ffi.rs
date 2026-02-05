// BuildToValue v2.0 - FFI Bridge for Validators
// Expõe validators Rust para Python via C ABI
//
// Architecture: Rust (validators) → C ABI → Python (ctypes/PyO3)
//
// Author: BuildToValue Architecture Team
// License: Apache 2.0

use crate::validators::{
    ConsentValidator, ConsentRevocationValidator, SensitiveDataValidator,
    CPFValidator, CNPJValidator, CreditCardValidator, Validator,
};
use crate::core::types::Finding;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;
use serde_json;

// ═══════════════════════════════════════════════════════════════════════════
// FFI STRUCTURES (C-compatible)
// ═══════════════════════════════════════════════════════════════════════════

/// FFI-compatible Finding structure
#[repr(C)]
pub struct FFIFinding {
    pub rule_id: *mut c_char,
    pub title: *mut c_char,
    pub description: *mut c_char,
    pub severity: u8,
    pub confidence: u8,
    pub validator_module: *mut c_char,
    pub metadata: *mut c_char,
}

impl FFIFinding {
    fn from_finding(finding: &Finding) -> Self {
        let severity_value = match finding.severity {
            crate::core::types::TechnicalSeverity::Critical(v) => v,
            crate::core::types::TechnicalSeverity::High(v) => v,
            crate::core::types::TechnicalSeverity::Medium(v) => v,
            crate::core::types::TechnicalSeverity::Low(v) => v,
        };

        Self {
            rule_id: CString::new(finding.rule_id.clone()).unwrap().into_raw(),
            title: CString::new(finding.title.clone()).unwrap().into_raw(),
            description: CString::new(finding.description.clone()).unwrap().into_raw(),
            severity: severity_value,
            confidence: finding.confidence,
            validator_module: CString::new(format!("{:?}", finding.module))
                .unwrap()
                .into_raw(),
            metadata: finding
                .metadata
                .as_ref()
                .map(|m| CString::new(m.clone()).unwrap().into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }
}

/// FFI-compatible result array
#[repr(C)]
pub struct FFIValidationResult {
    pub findings: *mut FFIFinding,
    pub findings_count: usize,
    pub error_message: *mut c_char,
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER: Parse metadata JSON to HashMap
// ═══════════════════════════════════════════════════════════════════════════

fn parse_metadata_json(json_str: &str) -> Result<HashMap<String, String>, String> {
    serde_json::from_str::<HashMap<String, String>>(json_str)
        .map_err(|e| format!("Failed to parse metadata JSON: {}", e))
}

// ═══════════════════════════════════════════════════════════════════════════
// FFI EXPORTS - LGPD VALIDATORS
// ═══════════════════════════════════════════════════════════════════════════

/// Consent Validator (LGPD Art. 7º, I)
///
/// # Safety
/// - input: valid UTF-8 C string
/// - metadata_json: valid JSON string (or null)
/// - Caller must free returned FFIValidationResult with free_validation_result()
#[no_mangle]
pub unsafe extern "C" fn validate_consent(
    input: *const c_char,
    metadata_json: *const c_char,
) -> FFIValidationResult {
    // Parse input
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => {
            return FFIValidationResult {
                findings: std::ptr::null_mut(),
                findings_count: 0,
                error_message: CString::new("Invalid UTF-8 input").unwrap().into_raw(),
            };
        }
    };

    // Parse metadata (optional)
    let metadata = if !metadata_json.is_null() {
        match CStr::from_ptr(metadata_json).to_str() {
            Ok(json) => match parse_metadata_json(json) {
                Ok(m) => Some(m),
                Err(e) => {
                    return FFIValidationResult {
                        findings: std::ptr::null_mut(),
                        findings_count: 0,
                        error_message: CString::new(e).unwrap().into_raw(),
                    };
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };

    // Run validator
    let validator = ConsentValidator::default();
    let findings = validator.validate(input_str, metadata.as_ref());

    // Convert to FFI
    convert_findings_to_ffi(findings)
}

/// Consent Revocation Validator (LGPD Art. 8º, § 5º)
#[no_mangle]
pub unsafe extern "C" fn validate_consent_revocation(
    input: *const c_char,
    metadata_json: *const c_char,
) -> FFIValidationResult {
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => {
            return FFIValidationResult {
                findings: std::ptr::null_mut(),
                findings_count: 0,
                error_message: CString::new("Invalid UTF-8 input").unwrap().into_raw(),
            };
        }
    };

    let metadata = if !metadata_json.is_null() {
        match CStr::from_ptr(metadata_json).to_str() {
            Ok(json) => match parse_metadata_json(json) {
                Ok(m) => Some(m),
                Err(e) => {
                    return FFIValidationResult {
                        findings: std::ptr::null_mut(),
                        findings_count: 0,
                        error_message: CString::new(e).unwrap().into_raw(),
                    };
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };

    let validator = ConsentRevocationValidator;
    let findings = validator.validate(input_str, metadata.as_ref());

    convert_findings_to_ffi(findings)
}

/// Sensitive Data Validator (LGPD Art. 11)
#[no_mangle]
pub unsafe extern "C" fn validate_sensitive_data(
    input: *const c_char,
    metadata_json: *const c_char,
) -> FFIValidationResult {
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => {
            return FFIValidationResult {
                findings: std::ptr::null_mut(),
                findings_count: 0,
                error_message: CString::new("Invalid UTF-8 input").unwrap().into_raw(),
            };
        }
    };

    let metadata = if !metadata_json.is_null() {
        match CStr::from_ptr(metadata_json).to_str() {
            Ok(json) => match parse_metadata_json(json) {
                Ok(m) => Some(m),
                Err(e) => {
                    return FFIValidationResult {
                        findings: std::ptr::null_mut(),
                        findings_count: 0,
                        error_message: CString::new(e).unwrap().into_raw(),
                    };
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };

    let validator = SensitiveDataValidator::default();
    let findings = validator.validate(input_str, metadata.as_ref());

    convert_findings_to_ffi(findings)
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH VALIDATION (Performance optimization)
// ═══════════════════════════════════════════════════════════════════════════

/// Batch validate with multiple validators (< 10ms for 100 inputs)
///
/// # Safety
/// - validator_names: comma-separated string ("consent,sensitive_data,cpf")
/// - inputs: array of C strings
/// - inputs_count: length of inputs array
/// - metadata_json: single JSON for all inputs
#[no_mangle]
pub unsafe extern "C" fn validate_batch(
    validator_names: *const c_char,
    inputs: *const *const c_char,
    inputs_count: usize,
    metadata_json: *const c_char,
) -> FFIValidationResult {
    // Parse validator names
    let validators_str = match CStr::from_ptr(validator_names).to_str() {
        Ok(s) => s,
        Err(_) => {
            return FFIValidationResult {
                findings: std::ptr::null_mut(),
                findings_count: 0,
                error_message: CString::new("Invalid validator names").unwrap().into_raw(),
            };
        }
    };

    // Parse metadata
    let metadata = if !metadata_json.is_null() {
        match CStr::from_ptr(metadata_json).to_str() {
            Ok(json) => match parse_metadata_json(json) {
                Ok(m) => Some(m),
                Err(e) => {
                    return FFIValidationResult {
                        findings: std::ptr::null_mut(),
                        findings_count: 0,
                        error_message: CString::new(e).unwrap().into_raw(),
                    };
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };

    // Convert inputs
    let input_ptrs = slice::from_raw_parts(inputs, inputs_count);
    let mut all_findings = Vec::new();

    for &input_ptr in input_ptrs {
        let input_str = match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Run each validator
        for validator_name in validators_str.split(',') {
            let findings = match validator_name.trim() {
                "consent" => {
                    let v = ConsentValidator::default();
                    v.validate(input_str, metadata.as_ref())
                }
                "consent_revocation" => {
                    let v = ConsentRevocationValidator;
                    v.validate(input_str, metadata.as_ref())
                }
                "sensitive_data" => {
                    let v = SensitiveDataValidator::default();
                    v.validate(input_str, metadata.as_ref())
                }
                "cpf" => {
                    let v = CPFValidator::default();
                    v.validate(input_str, metadata.as_ref())
                }
                "cnpj" => {
                    let v = CNPJValidator::default();
                    v.validate(input_str, metadata.as_ref())
                }
                "credit_card" => {
                    let v = CreditCardValidator::default();
                    v.validate(input_str, metadata.as_ref())
                }
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

/// Free FFIValidationResult (MUST be called by Python)
///
/// # Safety
/// - result must be obtained from validate_* functions
/// - Can only be called once per result
#[no_mangle]
pub unsafe extern "C" fn free_validation_result(result: FFIValidationResult) {
    if !result.findings.is_null() {
        let findings_slice = slice::from_raw_parts_mut(result.findings, result.findings_count);

        for finding in findings_slice {
            if !finding.rule_id.is_null() {
                let _ = CString::from_raw(finding.rule_id);
            }
            if !finding.title.is_null() {
                let _ = CString::from_raw(finding.title);
            }
            if !finding.description.is_null() {
                let _ = CString::from_raw(finding.description);
            }
            if !finding.validator_module.is_null() {
                let _ = CString::from_raw(finding.validator_module);
            }
            if !finding.metadata.is_null() {
                let _ = CString::from_raw(finding.metadata);
            }
        }

        let _ = Vec::from_raw_parts(result.findings, result.findings_count, result.findings_count);
    }

    if !result.error_message.is_null() {
        let _ = CString::from_raw(result.error_message);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn convert_findings_to_ffi(findings: Vec<Finding>) -> FFIValidationResult {
    if findings.is_empty() {
        return FFIValidationResult {
            findings: std::ptr::null_mut(),
            findings_count: 0,
            error_message: std::ptr::null_mut(),
        };
    }

    let ffi_findings: Vec<FFIFinding> = findings.iter().map(FFIFinding::from_finding).collect();

    let findings_count = ffi_findings.len();
    let findings_ptr = Box::into_raw(ffi_findings.into_boxed_slice()) as *mut FFIFinding;

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
    fn test_ffi_consent_validator() {
        let input = CString::new("").unwrap();
        let metadata = CString::new(r#"{"user.has_consent": "false", "processing.requires_consent": "true"}"#).unwrap();

        unsafe {
            let result = validate_consent(input.as_ptr(), metadata.as_ptr());

            assert!(result.error_message.is_null());
            assert_eq!(result.findings_count, 1);

            free_validation_result(result);
        }
    }

    #[test]
    fn test_ffi_sensitive_data_validator() {
        let input = CString::new("Paciente tem diagnóstico de diabetes").unwrap();

        unsafe {
            let result = validate_sensitive_data(input.as_ptr(), std::ptr::null());

            assert!(result.error_message.is_null());
            assert_eq!(result.findings_count, 1);

            free_validation_result(result);
        }
    }
}
