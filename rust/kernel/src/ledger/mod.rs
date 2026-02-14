//! Ledger Module v2.3.2
//!
//! Módulo responsável pela persistência segura, imutável e auditável dos eventos.
//!
//! Estrutura:
//! - `entry`: Definição dos dados (LedgerEntry)
//! - `wal`: Write-Ahead Log para durabilidade imediata (Crash Recovery)
//! - `durable_ledger`: Orquestrador principal (Disk + Remote)
//! - `remote`: Sincronização com Object Storage (S3)

pub mod durable_ledger;
pub mod entry;
pub mod wal;
pub mod remote;

pub use durable_ledger::{DurableLedger};
pub use entry::{LedgerEntry, ActionType};
// ✅ CORREÇÃO: Exportando WalEntry para ser visível pelo sync.rs e bridge
pub use wal::{WriteAheadLog, WalEntry};

// ✅ CORREÇÃO: Re-exports do S3 devem ser guardados pela feature flag
#[cfg(feature = "s3")]
pub use remote::{S3Connector, S3Config};