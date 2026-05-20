
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BiasDeclarationError {
    #[error("calibration_date is required (YYYYMMDD); got 0")]
    MissingCalibrationDate,
    #[error("test_dataset_size must be > 0")]
    MissingDatasetSize,
}

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