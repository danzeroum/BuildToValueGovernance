//! Remote Sync Module

#[cfg(feature = "remote-sync")]
pub mod sync;

#[cfg(feature = "s3")]
pub mod s3_connector;

#[cfg(feature = "remote-sync")]
pub use sync::{
    create_remote_sync,
    RemoteSyncService,
    RemoteConfig,
    StorageType
};

#[cfg(feature = "s3")]
pub use s3_connector::{S3Connector, S3Config, S3Error};