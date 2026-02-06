//! Communication Validators
//! Detecta informações de contato (email, telefone).

pub mod email;
pub mod phone;

pub use email::EmailValidator;
pub use phone::PhoneValidator;