//! `btv-judicial` — Poder Judiciário da República Algorítmica.
//!
//! Verifica decisões sem executá-las, sem legislar, e sem depender do Executivo.
//!
//! **Invariante constitucional** (Paper 5, Theorem 3.4):
//!   - Importa `btv-types` APENAS
//!   - Consulta `btv-sigma` diretamente via HTTP (nunca através do Executivo)
//!   - Assina relatórios com chave Ed25519 **independente** de L e E
//!
//! Verificado em CI por:
//!   `! cargo tree -p btv-judicial | grep btv-core`
#![deny(unsafe_code)]
#![deny(unused_must_use)]

pub mod audit_report;
pub mod compliance_check;
pub mod ed25519_verify;
pub mod hmac_verify;
pub mod ledger_query;
pub mod merkle_verify;
pub mod monitor;
pub mod payload_verify;
pub mod redaction_verify;

pub use audit_report::{AuditReport, FailureDetail, JudicialAuditor};
pub use ed25519_verify::ReceiptVerifier;
pub use hmac_verify::{HmacVerifier, JudicialError};
pub use ledger_query::LedgerQuery;
pub use merkle_verify::{verify_merkle_inclusion, verify_root_consistency};
pub use monitor::{Monitor, VerifiedPayload};
