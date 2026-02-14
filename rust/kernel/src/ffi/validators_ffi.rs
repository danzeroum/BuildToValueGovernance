// BuildToValue v2.0 - FFI Bridge for Validators
// Expõe validators Rust para Python via C ABI
//
// Architecture: Rust (validators) → C ABI → Python (ctypes/PyO3)
//
// Author: BuildToValue Architecture Team
// License: Apache 2.0
#![cfg(feature = "ffi-bindings")]
use crate::validators::{
    ConsentValidator, ConsentRevocationValidator, SensitiveDataValidator,
    CpfValidator, CnpjValidator, CreditCardValidator, Validator,
};
use crate::evidence::Finding;
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
        // ✅ FIX: Uso de to_u8() para tratar TechnicalSeverity corretamente
        let severity_value = finding.severity.to_u8();

        // Helper para converter arrays de bytes fixos (do Finding v2.3.2) para CString
        let bytes_to_cstring = |bytes: &[u8]| -> *mut c_char {
            let s = String::from_utf8_lossy(bytes)
                .trim_matches('\0')
                .to_string();
            CString::new(s).unwrap().into_raw()
        };

        // ✅ FIX: Mapeamento de campos v2.3.2 para estrutura legado da FFI
        // Finding não tem mais title/description strings, usamos threat_category e matched_text
        Self {
            rule_id: bytes_to_cstring(&finding.rule_id),
            title: bytes_to_cstring(&finding.threat_category), // Map threat -> title
            description: bytes_to_cstring(&finding.matched_text), // Map matched -> description
            severity: severity_value,
            confidence: finding.confidence,
            validator_module: CString::new(format!("{:?}", finding.module))
                .unwrap()
                .into_raw(),
            metadata: std::ptr::null_mut(), // Metadata foi removido do Finding v2.3.2
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
#[no_mangle]
pub unsafe extern "C" fn validate_consent(
    input: *const c_char,
    _metadata_json: *const c_char, // Ignorado na v2.3.2 (Metadata processado no Python/Gatekeeper)
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

    // ✅ FIX: .validate() agora aceita apenas input_str
    let validator = ConsentValidator::default();
    let findings = validator.validate(input_str);

    convert_findings_to_ffi(findings)
}

/// Consent Revocation Validator (LGPD Art. 8º, § 5º)
#[no_mangle]
pub unsafe extern "C" fn validate_consent_revocation(
    input: *const c_char,
    _metadata_json: *const c_char,
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

    let validator = ConsentRevocationValidator;
    let findings = validator.validate(input_str);

    convert_findings_to_ffi(findings)
}

/// Sensitive Data Validator (LGPD Art. 11)
#[no_mangle]
pub unsafe extern "C" fn validate_sensitive_data(
    input: *const c_char,
    _metadata_json: *const c_char,
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

    let validator = SensitiveDataValidator::default();
    let findings = validator.validate(input_str);

    convert_findings_to_ffi(findings)
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH VALIDATION (Performance optimization)
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
        Err(_) => {
            return FFIValidationResult {
                findings: std::ptr::null_mut(),
                findings_count: 0,
                error_message: CString::new("Invalid validator names").unwrap().into_raw(),
            };
        }
    };

    let input_ptrs = slice::from_raw_parts(inputs, inputs_count);
    let mut all_findings = Vec::new();

    for &input_ptr in input_ptrs {
        let input_str = match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };

        for validator_name in validators_str.split(',') {
            let findings = match validator_name.trim() {
                "consent" => {
                    let v = ConsentValidator::default();
                    v.validate(input_str)
                }
                "consent_revocation" => {
                    let v = ConsentRevocationValidator;
                    v.validate(input_str)
                }
                "sensitive_data" => {
                    let v = SensitiveDataValidator::default();
                    v.validate(input_str)
                }
                "cpf" => {
                    // ✅ FIX: Nome correto da struct CpfValidator (CamelCase)
                    let v = CpfValidator::default();
                    v.validate(input_str)
                }
                "cnpj" => {
                    // ✅ FIX: Nome correto da struct CnpjValidator
                    let v = CnpjValidator::default();
                    v.validate(input_str)
                }
                "credit_card" => {
                    let v = CreditCardValidator::default();
                    v.validate(input_str)
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

#[no_mangle]
pub unsafe extern "C" fn free_validation_result(result: FFIValidationResult) {
    if !result.findings.is_null() {
        let findings_slice = slice::from_raw_parts_mut(result.findings, result.findings_count);

        for finding in findings_slice {
            // Libera strings alocadas pelo CString::into_raw()
            if !finding.rule_id.is_null() { let _ = CString::from_raw(finding.rule_id); }
            if !finding.title.is_null() { let _ = CString::from_raw(finding.title); }
            if !finding.description.is_null() { let _ = CString::from_raw(finding.description); }
            if !finding.validator_module.is_null() { let _ = CString::from_raw(finding.validator_module); }
            if !finding.metadata.is_null() { let _ = CString::from_raw(finding.metadata); }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_ffi_consent_validator() {
        let input = CString::new("").unwrap();
        // Metadata ignorado na v2.3.2, passamos null
        unsafe {
            let result = validate_consent(input.as_ptr(), std::ptr::null());

            // Dependendo do input vazio, pode gerar finding ou não.
            // Apenas verificamos se não crasha e se podemos liberar.
            free_validation_result(result);
        }
    }
}