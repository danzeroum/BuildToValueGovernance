//! Interceptor Module v1.8.0 (ADR-015)
//! Adicionado: tool_screen (PROP-034a) — heurístico Rust puro.
pub mod hooks;
pub mod tool_screen;

pub use hooks::{
    RequestInterceptor, ResponseInterceptor,
    InterceptorChain, InterceptResult, InterceptAction, MaxLengthHook
};
pub use tool_screen::{ToolScreen, ToolScreenResult};
