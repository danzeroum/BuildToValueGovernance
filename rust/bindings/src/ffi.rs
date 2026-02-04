#[no_mangle]
pub extern "C" fn scan_for_evidence(
    input_ptr: *const u8,
    input_len: usize,
    output_ptr: *mut TechnicalEvidence,
) -> i32 {
    // ...
}