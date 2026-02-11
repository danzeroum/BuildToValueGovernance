// BuildToValue v2.0 - FFI Bridge for Validators
// Expõe validators Rust para Python via C ABI
//
// Architecture: Rust (validators) → C ABI → Python (ctypes/PyO3)
//
// Author: BuildToValue Architecture Team
// License: Apache 2.0

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
        // Helper para converter arrays de bytes fixos (do Finding v2.3.2) para CString
        // Trunca no primeiro byte nulo (0) ou usa a string inteira
        let bytes_to_cstring = |bytes: &[u8]| -> *mut c_char {
            let s = String::from_utf8_lossy(bytes)
                .trim_matches('\0')
                .to_string();
            CString::new(s).unwrap_or_default().into_raw()
        };

        // ✅ FIX: Uso de to_u8() em vez de match manual incorreto
        // TechnicalSeverity::High não tem campos, então High(v) causava erro E0023
        let severity_value = finding.severity.to_u8();

        // ✅ FIX: Mapeamento de campos v2.3.2 (arrays) para campos legado da FFI (pointers)
        Self {
            rule_id: bytes_to_cstring(&finding.rule_id),

            // Map threat_category -> title
            title: bytes_to_cstring(&finding.threat_category),

            // Map matched_text -> description
            description: bytes_to_cstring(&finding.matched_text),

            severity: severity_value,
            confidence: finding.confidence,

            validator_module: CString::new(format!("{:?}", finding.module))
                .unwrap_or_default()
                .into_raw(),

            // Metadata removido do Kernel v2.3.2, retornamos null para compatibilidade FFI
            metadata: std::ptr::null_mut(),
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
    metadata_json: *const c_char,
) -> FFIValidationResult {
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return error_result("Invalid UTF-8 input"),
    };

    let metadata = parse_metadata_opt(metadata_json);
    if let Err(e) = metadata {
        return error_result(&e);
    }
    let metadata = metadata.unwrap();

    let validator = ConsentValidator::default();
    // ✅ FIX: Passando 2 argumentos (input + metadata)
    let findings = validator.validate(input_str, metadata.as_ref());

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
        Err(_) => return error_result("Invalid UTF-8 input"),
    };

    let metadata = parse_metadata_opt(metadata_json);
    if let Err(e) = metadata {
        return error_result(&e);
    }
    let metadata = metadata.unwrap();

    let validator = ConsentRevocationValidator;
    // ✅ FIX: Passando 2 argumentos
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
        Err(_) => return error_result("Invalid UTF-8 input"),
    };

    let metadata = parse_metadata_opt(metadata_json);
    if let Err(e) = metadata {
        return error_result(&e);
    }
    let metadata = metadata.unwrap();

    let validator = SensitiveDataValidator::default();
    // ✅ FIX: Passando 2 argumentos
    let findings = validator.validate(input_str, metadata.as_ref());

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
    metadata_json: *const c_char,
) -> FFIValidationResult {
    let validators_str = match CStr::from_ptr(validator_names).to_str() {
        Ok(s) => s,
        Err(_) => return error_result("Invalid validator names"),
    };

    let metadata = parse_metadata_opt(metadata_json);
    if let Err(e) = metadata {
        return error_result(&e);
    }
    let metadata = metadata.unwrap();

    let input_ptrs = slice::from_raw_parts(inputs, inputs_count);
    let mut all_findings = Vec::new();

    for &input_ptr in input_ptrs {
        let input_str = match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => continue, // Skip invalid inputs in batch
        };

        for validator_name in validators_str.split(',') {
            // ✅ FIX: Nomes de tipos corrigidos (CamelCase) e 2 argumentos
            let findings = match validator_name.trim() {
                "consent" => ConsentValidator::default().validate(input_str, metadata.as_ref()),
                "consent_revocation" => ConsentRevocationValidator.validate(input_str, metadata.as_ref()),
                "sensitive_data" => SensitiveDataValidator::default().validate(input_str, metadata.as_ref()),
                "cpf" => CpfValidator::default().validate(input_str, metadata.as_ref()),   // Era CPFValidator
                "cnpj" => CnpjValidator::default().validate(input_str, metadata.as_ref()), // Era CNPJValidator
                "credit_card" => CreditCardValidator::default().validate(input_str, metadata.as_ref()),
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

unsafe fn parse_metadata_opt(json_ptr: *const c_char) -> Result<Option<HashMap<String, String>>, String> {
    if json_ptr.is_null() {
        return Ok(None);
    }
    match CStr::from_ptr(json_ptr).to_str() {
        Ok(json) => match parse_metadata_json(json) {
            Ok(m) => Ok(Some(m)),
            Err(e) => Err(e),
        },
        Err(_) => Ok(None),
    }
}

fn error_result(msg: &str) -> FFIValidationResult {
    FFIValidationResult {
        findings: std::ptr::null_mut(),
        findings_count: 0,
        error_message: CString::new(msg).unwrap_or_default().into_raw(),
    }
}

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
        let metadata = CString::new(r#"{"user.has_consent": "false"}"#).unwrap();

        unsafe {
            let result = validate_consent(input.as_ptr(), metadata.as_ptr());
            // Apenas verifica se não crasha e se a memória é liberada
            free_validation_result(result);
        }
    }
}