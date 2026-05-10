//! BuildToValue (BTV) — Public API Façade
//!
//! Este crate é uma abstração de custo zero (zero-cost facade).
//! Nenhuma lógica deve ser implementada aqui.
//!
//! O núcleo criptográfico reside em `btv-core`.
//! Esta facade expõe a API pública sob o nome comercial `buildtovalue`
//! sem introduzir overhead de compilação ou de runtime.
//!
//! # Uso
//! ```toml
//! [dependencies]
//! buildtovalue = "3.0.0-alpha.1"
//! ```
//!
//! ```rust,no_run
//! use buildtovalue::*;
//! ```

// Re-exporta toda a API pública do núcleo criptográfico.
// Custo: zero. O compilador inline esta re-exportação.
#[doc(inline)]
pub use btv_core::*;
