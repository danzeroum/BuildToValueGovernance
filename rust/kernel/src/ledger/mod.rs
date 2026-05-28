//! Ledger Module v1.1.0
//! Adicionado: session_agg (PROP-005) — Session Aggregator para Fourth Estate.
pub mod durable_ledger;
pub mod effect_log;
pub mod entry;
pub mod wal;
pub mod remote;
pub mod session_agg;
pub mod tenant_router;

pub use durable_ledger::DurableLedger;
pub use effect_log::{
    EffectEntry, EffectLog, EffectResult, AbortReason,
    Reversibility, Temporality, WalWriter, FrontierSet,
    EFFECT_RING_CAPACITY, MAX_FRONTIERS,
};
pub use entry::{LedgerEntry, ActionType};
pub use wal::{WriteAheadLog, WalConfig};
pub use session_agg::{SessionAggregator, SessionAggregate, SessionEvent, SESSION_RING_CAPACITY};
pub use tenant_router::{TenantStorageRouter, RouterError, DEFAULT_TENANT_ID, validate_tenant_claim};

#[cfg(feature = "s3")]
pub use remote::s3_connector::S3Connector;
