//! FFI Security Module
//!
//! Implementa segurança em chamadas FFI Python ↔ Rust:
//! - Bounds checking estático
//! - Integridade via BLAKE3
//! - Timestamp validation
//! - Zero-copy quando possível
//!
//! Security Level: MAXIMUM
//! Gate: G1 (FFI Safety Review)

use blake3::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════
// ERROS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Error, Debug)]
pub enum FFIError {
    #[error("Buffer overflow: size {actual} exceeds maximum {max}")]
    BufferOverflow { actual: usize, max: usize },

    #[error("Integrity violation: checksum mismatch")]
    IntegrityViolation,

    #[error("Stale data: timestamp {age}s exceeds maximum {max}s")]
    StaleData { age: u64, max: u64 },

    #[error("Invalid buffer: {reason}")]
    InvalidBuffer { reason: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type FFIResult<T> = Result<T, FFIError>;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTES DE SEGURANÇA
// ═══════════════════════════════════════════════════════════════════════════

/// Tamanho máximo de buffer FFI (1MB)
pub const MAX_BUFFER_SIZE: usize = 1024 * 1024;

/// Idade máxima de dados (30 segundos)
pub const MAX_DATA_AGE_SECS: u64 = 30;

/// Tamanho do hash BLAKE3 (32 bytes)
pub const BLAKE3_HASH_SIZE: usize = 32;

// ═══════════════════════════════════════════════════════════════════════════
// FFI BUFFER SEGURO
// ═══════════════════════════════════════════════════════════════════════════

/// Buffer FFI com garantias de segurança.
///
/// Garante:
/// - Tamanho máximo respeitado (anti-overflow)
/// - Integridade via BLAKE3 checksum
/// - Freshness via timestamp
/// - Alocação fixa (no heap growth)
#[derive(Debug, Clone)]
pub struct FFIBuffer {
    /// Dados do buffer
    data: Vec<u8>,

    /// Checksum BLAKE3 dos dados
    checksum: [u8; BLAKE3_HASH_SIZE],

    /// Timestamp de criação (Unix epoch seconds)
    timestamp: u64,

    /// Metadados opcionais (para debugging)
    metadata: Option<BufferMetadata>,
}

#[derive(Debug, Clone)]
pub struct BufferMetadata {
    pub source: String,
    pub operation: String,
    pub sequence: u64,
}

impl FFIBuffer {
    /// Cria buffer a partir de dados Python.
    ///
    /// # Security
    /// - Valida tamanho máximo
    /// - Calcula checksum BLAKE3
    /// - Adiciona timestamp
    /// - Valida integridade imediatamente
    ///
    /// # Errors
    /// - `BufferOverflow` se dados excedem MAX_BUFFER_SIZE
    /// - `IntegrityViolation` se validação falhar
    pub fn from_python(data: &[u8]) -> FFIResult<Self> {
        // 1. Valida tamanho máximo
        if data.len() > MAX_BUFFER_SIZE {
            return Err(FFIError::BufferOverflow {
                actual: data.len(),
                max: MAX_BUFFER_SIZE,
            });
        }

        // 2. Calcula checksum BLAKE3
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let checksum: [u8; BLAKE3_HASH_SIZE] = *hash.as_bytes();

        // 3. Captura timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // 4. Cria buffer
        let buffer = Self {
            data: data.to_vec(),
            checksum,
            timestamp,
            metadata: None,
        };

        // 5. Valida integridade imediatamente
        buffer.validate()?;

        Ok(buffer)
    }

    /// Cria buffer com metadados.
    pub fn from_python_with_metadata(
        data: &[u8],
        metadata: BufferMetadata,
    ) -> FFIResult<Self> {
        let mut buffer = Self::from_python(data)?;
        buffer.metadata = Some(metadata);
        Ok(buffer)
    }

    /// Valida integridade do buffer.
    ///
    /// # Security
    /// - Verifica checksum BLAKE3
    /// - Valida freshness (não muito antigo)
    /// - Usa constant-time comparison para checksum
    ///
    /// # Errors
    /// - `IntegrityViolation` se checksum não bate
    /// - `StaleData` se timestamp muito antigo
    pub fn validate(&self) -> FFIResult<()> {
        // 1. Valida checksum
        let mut hasher = Hasher::new();
        hasher.update(&self.data);
        let computed = hasher.finalize();

        // Constant-time comparison (timing attack protection)
        if !constant_time_eq(&self.checksum, computed.as_bytes()) {
            return Err(FFIError::IntegrityViolation);
        }

        // 2. Valida freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let age = now.saturating_sub(self.timestamp);
        if age > MAX_DATA_AGE_SECS {
            return Err(FFIError::StaleData {
                age,
                max: MAX_DATA_AGE_SECS,
            });
        }

        Ok(())
    }

    /// Retorna dados (após validação).
    ///
    /// # Security
    /// Sempre valida antes de retornar dados.
    pub fn data(&self) -> FFIResult<&[u8]> {
        self.validate()?;
        Ok(&self.data)
    }

    /// Retorna dados como Vec (owned).
    pub fn into_data(self) -> FFIResult<Vec<u8>> {
        self.validate()?;
        Ok(self.data)
    }

    /// Retorna checksum.
    pub fn checksum(&self) -> &[u8; BLAKE3_HASH_SIZE] {
        &self.checksum
    }

    /// Retorna timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Retorna metadados.
    pub fn metadata(&self) -> Option<&BufferMetadata> {
        self.metadata.as_ref()
    }

    /// Tamanho dos dados.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Verifica se está vazio.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Calcula hash BLAKE3 dos dados.
    pub fn hash(&self) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(&self.data);
        hasher.finalize()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FFI BATCH PROCESSOR
// ═══════════════════════════════════════════════════════════════════════════

/// Processa múltiplos buffers em batch (otimização).
///
/// Usado para enviar múltiplos findings de uma vez via FFI.
pub struct FFIBatchProcessor {
    buffers: Vec<FFIBuffer>,
    max_batch_size: usize,
}

impl FFIBatchProcessor {
    /// Cria novo batch processor.
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(max_batch_size),
            max_batch_size,
        }
    }

    /// Adiciona buffer ao batch.
    pub fn add(&mut self, buffer: FFIBuffer) -> FFIResult<()> {
        if self.buffers.len() >= self.max_batch_size {
            return Err(FFIError::InvalidBuffer {
                reason: format!(
                    "Batch full: {} items",
                    self.buffers.len()
                ),
            });
        }

        buffer.validate()?;
        self.buffers.push(buffer);
        Ok(())
    }

    /// Valida todos os buffers no batch.
    pub fn validate_all(&self) -> FFIResult<()> {
        for buffer in &self.buffers {
            buffer.validate()?;
        }
        Ok(())
    }

    /// Retorna buffers (após validação).
    pub fn buffers(&self) -> FFIResult<&[FFIBuffer]> {
        self.validate_all()?;
        Ok(&self.buffers)
    }

    /// Consome batch e retorna buffers.
    pub fn into_buffers(self) -> FFIResult<Vec<FFIBuffer>> {
        self.validate_all()?;
        Ok(self.buffers)
    }

    /// Número de buffers no batch.
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// Verifica se batch está vazio.
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// Limpa batch.
    pub fn clear(&mut self) {
        self.buffers.clear();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/// Comparação constant-time (timing attack protection).
///
/// Usa XOR bit-a-bit para garantir tempo constante.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_creation() {
        let data = b"Hello, World!";
        let buffer = FFIBuffer::from_python(data).unwrap();

        assert_eq!(buffer.len(), data.len());
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_buffer_integrity() {
        let data = b"Test data";
        let buffer = FFIBuffer::from_python(data).unwrap();

        // Validação deve passar
        assert!(buffer.validate().is_ok());

        // Dados devem ser acessíveis
        assert_eq!(buffer.data().unwrap(), data);
    }

    #[test]
    fn test_buffer_overflow() {
        // Cria buffer maior que MAX_BUFFER_SIZE
        let large_data = vec![0u8; MAX_BUFFER_SIZE + 1];
        let result = FFIBuffer::from_python(&large_data);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FFIError::BufferOverflow { .. }));
    }

    #[test]
    fn test_checksum_validation() {
        let data = b"Test data";
        let mut buffer = FFIBuffer::from_python(data).unwrap();

        // Corrompe checksum
        buffer.checksum[0] ^= 0xFF;

        // Validação deve falhar
        assert!(buffer.validate().is_err());
        assert!(matches!(
            buffer.validate().unwrap_err(),
            FFIError::IntegrityViolation
        ));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"secret";
        let b = b"secret";
        let c = b"public";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
    }

    #[test]
    fn test_batch_processor() {
        let mut batch = FFIBatchProcessor::new(10);

        for i in 0..5 {
            let data = format!("Data {}", i);
            let buffer = FFIBuffer::from_python(data.as_bytes()).unwrap();
            batch.add(buffer).unwrap();
        }

        assert_eq!(batch.len(), 5);
        assert!(batch.validate_all().is_ok());
    }

    #[test]
    fn test_batch_overflow() {
        let mut batch = FFIBatchProcessor::new(2);

        // Adiciona 2 (ok)
        for i in 0..2 {
            let buffer = FFIBuffer::from_python(format!("Data {}", i).as_bytes()).unwrap();
            batch.add(buffer).unwrap();
        }

        // Terceiro deve falhar
        let buffer = FFIBuffer::from_python(b"Extra").unwrap();
        assert!(batch.add(buffer).is_err());
    }
}
