//! Network Validators
//! Detecta endereços de rede (IP, URLs, domínios).

pub mod ip;

pub use ip::{Ipv4Validator, UrlValidator};