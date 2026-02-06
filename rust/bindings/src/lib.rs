//! BuildToValue FFI Bindings
//! Gateway para interoperabilidade com Python e C.
//!
//! # Features
//! - `python`: Ativa bindings para Python via PyO3
//! - `c`: Ativa bindings C FFI
//!
//! # Exemplo Python
//! ```python
//! import buildtovalue_governance
//! result = buildtovalue_governance.calculate_penalties_batch([...])
//! ```

#![cfg_attr(feature = "c", allow(improper_ctypes))]

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "c")]
pub mod c;

// Re-export para conveniência
#[cfg(feature = "python")]
pub use python::*;

#[cfg(feature = "c")]
pub use c::*;