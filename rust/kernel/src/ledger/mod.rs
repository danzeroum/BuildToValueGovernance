pub mod durable_ledger;
pub mod entry;
pub mod wal;
pub mod remote;

pub use durable_ledger::{DurableLedger};
pub use entry::{LedgerEntry, ActionType};
pub use wal::{WriteAheadLog as WriteAheadLog, WalConfig};

// ✅ Correção: Só tenta re-exportar se a feature estiver ativa
#[cfg(feature = "s3")]
pub use remote::s3_connector::{S3Connector};