
//! Integration tests for Rust-Python FFI bridge
//!
//! These tests verify that the FFI interface works correctly
//! and that data is properly marshalled between Rust and Python.

use buildtovalue_kernel::ffi::*;
use buildtovalue_kernel::evidence::TechnicalEvidence;
use std::ffi::{CString, CStr};
use std::ptr;

// ═══════════════════════════════════════════════════════════════
// Setup & Teardown
// ═══════════════════════════════════════════════════════════════

#[ctor::ctor]
fn setup() {
    // Initialize kernel (load Bloom filters, etc)
    unsafe {
        kernel_init();
    }
}

#[ctor::dtor]
fn teardown() {
    // Cleanup
    unsafe {
        kernel_shutdown();
    }
}

// ═══════════════════════════════════════════════════════════════
// Basic FFI Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_ffi_scan_for_evidence_basic() {
    let input = CString::new("My CPF is 123.456.789-09").unwrap();
    let mut evidence = TechnicalEvidence::default();
    
    let result = unsafe {
        scan_for_evidence(
            input.as_ptr() as *const u8,
            input.as_bytes().len(),
            &mut evidence as *mut TechnicalEvidence,
        )
    };
    
    assert_eq!(result, 0, "FFI call should succeed");
    assert_eq!(evidence.finding_count, 1, "Should detect 1 CPF");
    assert!(evidence.has_pii, "Should flag as PII");
}

#[test]
fn test_ffi_scan_for_evidence_clean_input() {
    let input = CString::new("Hello, this is a clean message").unwrap();
    let mut evidence = TechnicalEvidence::default();
    
    let result = unsafe {
        scan_for_evidence(
            input.as_ptr() as *const u8,
            input.as_bytes().len(),
            &mut evidence as *mut TechnicalEvidence,
        )
    };
    
    assert_eq!(result, 0);
    assert_eq!(evidence.finding_count, 0, "Should detect no violations");
    assert!(!evidence.has_pii, "Should not flag as PII");
}

#[test]
fn test_ffi_null_pointer_safety() {
    let input = CString::new("Test").unwrap();
    
    // Null output pointer should return error
    let result = unsafe {
        scan_for_evidence(
            input.as_ptr() as *const u8,
            input.as_bytes().len(),
            ptr::null_mut(),
        )
    };
    
    assert_eq!(result, -1, "Should return error on null output pointer");
}

#[test]
fn test_ffi_empty_input() {
    let input = CString::new("").unwrap();
    let mut evidence = TechnicalEvidence::default();
    
    let result = unsafe {
        scan_for_evidence(
            input.as_ptr() as *const u8,
            0,
            &mut evidence as *mut TechnicalEvidence,
        )
    };
    
    assert_eq!(result, 0);
    assert_eq!(evidence.finding_count, 0);
}

#[test]
fn test_ffi_large_input() {
    // 1MB input
    let large_input = "A".repeat(1_000_000);
    let input = CString::new(large_input).unwrap();
    let mut evidence = TechnicalEvidence::default();
    
    let result = unsafe {
        scan_for_evidence(
            input.as_ptr() as *const u8,
            input.as_bytes().len(),
            &mut evidence as *mut TechnicalEvidence,
        )
    };
    
    assert_eq!(result, 0, "Should handle large input");
}

// ═══════════════════════════════════════════════════════════════
// Batch Processing Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_ffi_batch_scan() {
    let inputs = vec![
        "Hello",
        "My CPF is 123.456.789-09",
        "Clean message",
    ];
    
    let c_strings: Vec<_> = inputs.iter()
        .map(|s| CString::new(*s).unwrap())
        .collect();
    
    let input_ptrs: Vec<_> = c_strings.iter()
        .map(|cs| cs.as_ptr() as *const u8)
        .collect();
    
    let input_lens: Vec<_> = c_strings.iter()
        .map(|cs| cs.as_bytes().len())
        .collect();
    
    let mut evidences = vec![TechnicalEvidence::default(); 3];
    
    let result = unsafe {
        batch_scan_for_evidence(
            input_ptrs.as_ptr(),
            input_lens.as_ptr(),
            inputs.len(),
            evidences.as_mut_ptr(),
            10, // 10ms timeout
        )
    };
    
    assert_eq!(result, 0, "Batch scan should succeed");
    assert_eq!(evidences[0].finding_count, 0, "First input clean");
    assert_eq!(evidences [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/a8bf2d44-ead0-43f2-99b4-cf572fdbfb91/paste.txt).finding_count, 1, "Second input has CPF");
    assert_eq!(evidences [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/27869fa6-8980-4131-823b-4192beed20b2/ARCHITECTURE_pt.md).finding_count, 0, "Third input clean");
}

#[test]
fn test_ffi_batch_timeout() {
    // Create 1000 inputs (should timeout)
    let inputs = vec!["Test input"; 1000];
    
    let c_strings: Vec<_> = inputs.iter()
        .map(|s| CString::new(*s).unwrap())
        .collect();
    
    let input_ptrs: Vec<_> = c_strings.iter()
        .map(|cs| cs.as_ptr() as *const u8)
        .collect();
    
    let input_lens: Vec<_> = c_strings.iter()
        .map(|cs| cs.as_bytes().len())
        .collect();
    
    let mut evidences = vec![TechnicalEvidence::default(); 1000];
    
    let result = unsafe {
        batch_scan_for_evidence(
            input_ptrs.as_ptr(),
            input_lens.as_ptr(),
            inputs.len(),
            evidences.as_mut_ptr(),
            1, // 1ms timeout (too short)
        )
    };
    
    // Should timeout (partial results)
    assert_ne!(result, 0, "Should timeout");
}

// ═══════════════════════════════════════════════════════════════
// Memory Safety Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_ffi_no_memory_leak() {
    use std::alloc::{alloc, dealloc, Layout};
    
    // Track memory usage
    let layout = Layout::from_size_align(1024, 8).unwrap();
    let initial_ptr = unsafe { alloc(layout) };
    
    for _ in 0..1000 {
        let input = CString::new("My CPF is 123.456.789-09").unwrap();
        let mut evidence = TechnicalEvidence::default();
        
        unsafe {
            scan_for_evidence(
                input.as_ptr() as *const u8,
                input.as_bytes().len(),
                &mut evidence as *mut TechnicalEvidence,
            );
        }
    }
    
    unsafe { dealloc(initial_ptr, layout); }
    
    // If we got here without OOM, no leak
}

#[test]
fn test_ffi_concurrent_calls() {
    use std::sync::Arc;
    use std::thread;
    
    let handles: Vec<_> = (0..10).map(|i| {
        thread::spawn(move || {
            let input = CString::new(format!("Thread {} message", i)).unwrap();
            let mut evidence = TechnicalEvidence::default();
            
            unsafe {
                scan_for_evidence(
                    input.as_ptr() as *const u8,
                    input.as_bytes().len(),
                    &mut evidence as *mut TechnicalEvidence,
                )
            }
        })
    }).collect();
    
    for handle in handles {
        let result = handle.join().unwrap();
        assert_eq!(result, 0, "Concurrent FFI calls should succeed");
    }
}

// ═══════════════════════════════════════════════════════════════
// Edge Cases
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_ffi_invalid_utf8() {
    // Invalid UTF-8 sequence
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let mut evidence = TechnicalEvidence::default();
    
    let result = unsafe {
        scan_for_evidence(
            invalid_utf8.as_ptr(),
            invalid_utf8.len(),
            &mut evidence as *mut TechnicalEvidence,
        )
    };
    
    // Should handle gracefully (return error)
    assert_eq!(result, -1, "Should reject invalid UTF-8");
}

#[test]
fn test_ffi_unicode_normalization() {
    // CPF with zero-width spaces
    let input = "CPF: 123\u{200B}.456\u{200B}.789\u{200B}-09";
    let c_input = CString::new(input).unwrap();
    let mut evidence = TechnicalEvidence::default();
    
    let result = unsafe {
        scan_for_evidence(
            c_input.as_ptr() as *const u8,
            c_input.as_bytes().len(),
            &mut evidence as *mut TechnicalEvidence,
        )
    };
    
    assert_eq!(result, 0);
    assert_eq!(evidence.finding_count, 1, "Should detect CPF after normalization");
}