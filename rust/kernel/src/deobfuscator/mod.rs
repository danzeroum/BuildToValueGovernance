//! Deobfuscator Module v2.3.2
//!
//! Detecta e decodifica tentativas de ofuscação de dados (Base64, Hex, Leetspeak).
//! Usado para revelar payloads maliciosos ou PII escondido antes da validação principal.
//! Deobfuscator Module v1.6.0 (ADR-013)
//!
//! Individual detectors + chaining (max 3 layers).

pub mod base64;
pub mod hex;
pub mod leetspeak;
pub mod chain;

pub use base64::Base64Detector;
pub use hex::HexDecoder;
pub use leetspeak::LeetspeakDetector;
pub use chain::DeobfuscatorChain;