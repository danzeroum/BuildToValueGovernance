//! Remote Sync Module v2.3.2
//!
//! Módulo responsável pela sincronização assíncrona do Ledger com armazenamento remoto (S3).
//!
//! Componentes:
//! - `s3_connector`: Cliente S3 com retry, backoff e DLQ (Requer feature "s3").
//! - `sync`: Serviço de background para upload em batch e não-bloqueante.

// ✅ CORREÇÃO: Protegendo módulo que depende de aws-sdk-s3 (opcional)
#[cfg(feature = "s3")]
pub mod s3_connector;

pub mod sync;

// ✅ CORREÇÃO: Re-exports protegidos e Typo corrigido (S3Connecto -> S3Connector)
#[cfg(feature = "s3")]
pub use s3_connector::{S3Connector, S3Config, S3Error};

pub use sync::{
    create_remote_sync,
    RemoteSyncService,
    RemoteConfig,
    StorageType
};