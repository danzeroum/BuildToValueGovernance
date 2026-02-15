//! Remote Sync Module - rust/kernel/src/ledger/remote/mod.rs

pub mod config;
#[cfg(feature = "s3")]
pub mod s3_connector;
#[cfg(feature = "remote-sync")]
pub mod sync;

// Re-exporta S3Config incondicionalmente para uso em outros módulos
pub use config::S3Config;

#[cfg(feature = "s3")]
pub use s3_connector::{ S3Error};
#[cfg(feature = "remote-sync")]
pub use sync::{RemoteSyncService, RemoteConfig};