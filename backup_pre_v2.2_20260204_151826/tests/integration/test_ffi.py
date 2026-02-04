def test_ffi_basic():
    result = ffi_client.scan_for_evidence("Test")
    assert result is not None
    
def test_ffi_large_input():
    large_input = "A" * 1_000_000
    result = ffi_client.scan_for_evidence(large_input)
    # Should not crash