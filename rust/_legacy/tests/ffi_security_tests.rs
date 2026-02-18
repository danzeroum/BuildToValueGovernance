//! Testes de segurança FFI (Property-based + Unit)

use buildtovalue_kernel::ffi_security::{
    FFIBuffer, FFIBatchProcessor, FFIError, MAX_BUFFER_SIZE
};
use proptest::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════
// TESTES UNITÁRIOS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_buffer_creation_valid() {
    let data = b"Hello, BuildToValue!";
    let buffer = FFIBuffer::from_python(data).unwrap();

    assert_eq!(buffer.len(), data.len());
    assert!(!buffer.is_empty());
    assert!(buffer.validate().is_ok());
}

#[test]
fn test_buffer_overflow_protection() {
    // Cria buffer maior que MAX_BUFFER_SIZE
    let large_data = vec![0u8; MAX_BUFFER_SIZE + 1];
    let result = FFIBuffer::from_python(&large_data);

    assert!(result.is_err());
    match result.unwrap_err() {
        FFIError::BufferOverflow { actual, max } => {
            assert_eq!(actual, MAX_BUFFER_SIZE + 1);
            assert_eq!(max, MAX_BUFFER_SIZE);
        }
        _ => panic!("Expected BufferOverflow error"),
    }
}

#[test]
fn test_checksum_integrity() {
    let data = b"Test data for integrity check";
    let buffer = FFIBuffer::from_python(data).unwrap();

    // Checksum deve ser válido
    assert!(buffer.validate().is_ok());

    // Acesso aos dados deve funcionar
    assert_eq!(buffer.data().unwrap(), data);
}

#[test]
fn test_checksum_tampering_detection() {
    let data = b"Original data";
    let mut buffer = FFIBuffer::from_python(data).unwrap();

    // Corrompe o checksum
    buffer.checksum[0] ^= 0xFF;

    // Validação deve falhar
    assert!(buffer.validate().is_err());
    assert!(matches!(
        buffer.validate().unwrap_err(),
        FFIError::IntegrityViolation
    ));
}

#[test]
fn test_batch_processor() {
    let mut batch = FFIBatchProcessor::new(100);

    // Adiciona 50 buffers
    for i in 0..50 {
        let data = format!("Buffer #{}", i);
        let buffer = FFIBuffer::from_python(data.as_bytes()).unwrap();
        batch.add(buffer).unwrap();
    }

    assert_eq!(batch.len(), 50);
    assert!(batch.validate_all().is_ok());
}

#[test]
fn test_batch_overflow() {
    let mut batch = FFIBatchProcessor::new(5);

    // Adiciona 5 (max)
    for i in 0..5 {
        let buffer = FFIBuffer::from_python(format!("Item {}", i).as_bytes()).unwrap();
        batch.add(buffer).unwrap();
    }

    // Sexto deve falhar
    let extra = FFIBuffer::from_python(b"Extra item").unwrap();
    assert!(batch.add(extra).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// PROPERTY-BASED TESTS (Fuzzing)
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Property: Qualquer buffer válido deve sempre validar.
    #[test]
    fn prop_valid_buffer_always_validates(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        if data.len() <= MAX_BUFFER_SIZE {
            let buffer = FFIBuffer::from_python(&data).unwrap();
            assert!(buffer.validate().is_ok());
        }
    }

    /// Property: Buffer overflow sempre detectado.
    #[test]
    fn prop_overflow_always_detected(
        extra_bytes in 1usize..1000
    ) {
        let size = MAX_BUFFER_SIZE + extra_bytes;
        let data = vec![0u8; size];

        let result = FFIBuffer::from_python(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FFIError::BufferOverflow { .. }));
    }

    /// Property: Checksum corruption sempre detectada.
    #[test]
    fn prop_checksum_corruption_detected(
        data in prop::collection::vec(any::<u8>(), 1..1024),
        corrupt_byte_idx in 0usize..32
    ) {
        let mut buffer = FFIBuffer::from_python(&data).unwrap();

        // Corrompe um byte do checksum
        buffer.checksum[corrupt_byte_idx] ^= 0xFF;

        // Deve falhar
        assert!(buffer.validate().is_err());
    }

    /// Property: Dados retornados sempre iguais aos originais.
    #[test]
    fn prop_data_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        if data.len() <= MAX_BUFFER_SIZE {
            let buffer = FFIBuffer::from_python(&data).unwrap();
            assert_eq!(buffer.data().unwrap(), &data[..]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BENCHMARKS (Performance)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;

    #[test]
    fn bench_buffer_creation() {
        let data = vec![0u8; 1024]; // 1KB
        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = FFIBuffer::from_python(&data).unwrap();
        }
        let elapsed = start.elapsed();

        let avg_us = elapsed.as_micros() / iterations;
        println!("Buffer creation: {} µs/op", avg_us);

        // SLA: <100µs por operação
        assert!(avg_us < 100, "Too slow: {} µs", avg_us);
    }

    #[test]
    fn bench_validation() {
        let data = vec![0u8; 1024];
        let buffer = FFIBuffer::from_python(&data).unwrap();
        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            buffer.validate().unwrap();
        }
        let elapsed = start.elapsed();

        let avg_us = elapsed.as_micros() / iterations;
        println!("Validation: {} µs/op", avg_us);

        // SLA: <50µs por validação
        assert!(avg_us < 50, "Too slow: {} µs", avg_us);
    }
}
