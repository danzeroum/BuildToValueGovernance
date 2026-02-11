// rust/kernel/src/api/mod.rs
pub mod response;
// Agora ValidationResult e ResponseType são públicos em response.rs
pub use response::{ValidationResult, ResponseType};