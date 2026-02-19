#![cfg(feature = "s3")]

use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ServerSideEncryption, StorageClass};
use std::time::{SystemTime, Duration};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::ledger::entry::LedgerEntry;
use super::config::S3Config;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIG & ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Error, Debug)]
pub enum S3Error {
    #[error("S3 upload failed after {retries} retries: {source}")]
    UploadFailed {
        retries: u32,
        #[source]
        source: aws_sdk_s3::Error,
    },

    #[error("S3 configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

// ═══════════════════════════════════════════════════════════════════════════
// S3 CONNECTOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct S3Connector {
    client: S3Client,
    config: S3Config,
    dlq: Mutex<Vec<LedgerEntry>>,
}

impl S3Connector {
    /// Cria novo conector S3
    pub async fn new(config: S3Config) -> Result<Self, S3Error> {
        // Atualizado para usar load_defaults (recomendado)
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::v2026_01_12()).await;

        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config)
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .force_path_style(config.force_path_style);

        if let Some(endpoint) = &config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        let client = S3Client::from_conf(s3_config_builder.build());

        Ok(Self {
            client,
            config,
            dlq: Mutex::new(Vec::new()),
        })
    }

    /// Upload de um único entry com Retry Logic
    pub async fn upload_entry(&self, entry: &LedgerEntry) -> Result<(), S3Error> {
        let key = self.generate_key(entry);

        let body_bytes = bincode::serialize(entry)
            .map_err(|e| S3Error::SerializationError(e.to_string()))?;

        let mut attempts = 0;
        let max_retries = 3;

        loop {
            attempts += 1;

            let body = ByteStream::from(body_bytes.clone());

            let result = self.client.put_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .body(body)
                .server_side_encryption(ServerSideEncryption::Aes256)
                .storage_class(StorageClass::Standard)
                .send()
                .await;

            match result {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if attempts >= max_retries {
                        let mut dlq = self.dlq.lock().await;
                        dlq.push(*entry);
                        return Err(S3Error::UploadFailed {
                            retries: attempts,
                            source: e.into(),
                        });
                    }

                    let backoff_exponent = attempts.saturating_sub(1);
                    let delay = 100 * 2_u64.pow(backoff_exponent);
                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }

    fn generate_key(&self, entry: &LedgerEntry) -> String {
        use chrono::{DateTime, Utc};
        let d = SystemTime::UNIX_EPOCH + Duration::from_micros(entry.timestamp as u64);
        let datetime: DateTime<Utc> = d.into();

        format!(
            "{}{}/{:02}/{:02}/{:016x}.bin",
            self.config.key_prefix,
            datetime.format("%Y"),
            datetime.format("%m"),
            datetime.format("%d"),
            entry.entry_id
        )
    }
}