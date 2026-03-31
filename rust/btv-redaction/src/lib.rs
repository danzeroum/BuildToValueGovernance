//! `btv-redaction` — Accountable Redaction via ZK-SNARKs.
//!
//! Implementa o protocolo de 4 fases do Paper 3:
//!   Phase 1: Authorization   — Ed25519 do titular dos dados
//!   Phase 2: State Commitment — Pedersen(antes) e Pedersen(depois)
//!   Phase 3: ZK Proof         — Circuito Noir (ε-statistical consistency)
//!   Phase 4: Receipt          — Persiste no Transparency Log (btv-sigma)
//!
//! **Invariante constitucional**: depende de `btv-types` APENAS.
//! Verificado em CI: `! cargo tree -p btv-redaction | grep btv-core`
//!
//! **Status da integração Noir**: Semanas 18-30 (ver roadmap em circuits/).
//! Mode atual: direct verification (sem ZK) para CI/testes unitários.
#![deny(unsafe_code)]
#![deny(unused_must_use)]

pub mod group_stats;
pub mod state_commitment;
pub mod authorized_redaction;
pub mod redaction_receipt;
pub mod protocol;
pub mod prover;
pub mod verifier;

pub use group_stats::{GroupStats, LedgerStatistics, RedactionEntry};
pub use state_commitment::{StateCommitment, RedactionCommitmentPair};
pub use protocol::{AccountableRedaction, RedactionConfig, RedactionError, RedactionResult};
pub use redaction_receipt::RedactionReceipt;
pub use verifier::RedactionVerifier;
