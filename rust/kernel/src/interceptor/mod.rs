//! Interceptor Module v1.7.0 (ADR-015)
pub mod hooks;
pub use hooks::{
    RequestInterceptor, ResponseInterceptor,
    InterceptorChain, InterceptResult, InterceptAction,MaxLengthHook
};