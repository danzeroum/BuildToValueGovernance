//! Brazilian Validators (LGPD Compliance)
//!
//! Detecta documentos brasileiros (CPF, CNPJ) conforme LGPD.

pub mod cpf;
pub mod cnpj;

pub use cpf::CpfValidator;
pub use cnpj::CnpjValidator;