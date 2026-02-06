//! Security Module
//! Módulos de segurança (sanitização, assinatura, etc.)

pub mod audit;
pub mod ffi_security;
pub mod input_sanitizer;
pub mod oblivious_cache;
pub mod signing;
pub mod timing_guard;

pub use audit::ProbingDetector;
pub use ffi_security::{FFIBuffer, FFIError};
pub use input_sanitizer::{InputSanitizer, SanitizationError};
pub use oblivious_cache::ObliviousCache;
pub use signing::{SigningKeyManager, CryptoError};
pub use timing_guard::TimingGuard;