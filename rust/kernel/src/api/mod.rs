// rust/kernel/src/api/mod.rs
pub mod response;
pub mod error_as_resource;

// Apenas tipos que compõem a resposta HTTP pública são re-exportados.
// Helpers internos permanecem com visibilidade de módulo (pub(crate))
// para não vazar para clientes do crate. Ver ADR-0082.
pub use response::{ValidationResult, ResponseType};
pub use error_as_resource::{
    EthicalError,
    BtvExtensions,
    SamplingMode,
    attach_rate_limit_headers,
    verdict_signature_header,
    PROBLEM_JSON_CONTENT_TYPE,
};