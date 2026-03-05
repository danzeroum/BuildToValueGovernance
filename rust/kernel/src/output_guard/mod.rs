//! Output Guard v1.6.0 — PII Masking + Re-scan (ADR-012)
pub mod sanitizer;
pub use sanitizer::{OutputSanitizer, SanitizeResult};
pub mod injection_guard;
pub use injection_guard::{screen_tool_output, InjectionSignal};
