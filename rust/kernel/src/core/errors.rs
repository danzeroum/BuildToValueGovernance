
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EvidenceError {
    #[error("Evidence already finalized")]
    AlreadyFinalized,
    
    #[error("Evidence not finalized")]
    NotFinalized,
    
    #[error("Invalid checksum")]
    InvalidChecksum,
    
    #[error("Protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u16, got: u16 },
    
    #[error("Findings buffer full")]
    BufferFull,
    
    #[error("Invalid UTF-8 in field: {field}")]
    InvalidUtf8 { field: String },
}