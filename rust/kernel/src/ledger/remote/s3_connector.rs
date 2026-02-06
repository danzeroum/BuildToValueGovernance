//! S3 Remote Sync Connector v2.3
//!
//! **PRIORIDADE 1**: Implementa upload real para S3 (substitui mock).
//!
//! Garante:
//! - 99.99% durabilidade (S3 Standard)
//! - Retry logic (3 tentativas, backoff exponencial)
//! - Dead Letter Queue para falhas persistentes
//! - Idempotência (mesmo entry_id = mesma chave S3)
//!
//! ADR: ADR-007 (Remote Sync Implementation)

use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ServerSideEncryption, StorageClass};
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

use crate::ledger::entry::LedgerEntry;

// ═══════════════════════════════════════════════════════════════════════════
// ERROS
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

    #[error("Dead letter queue full: {count} entries")]
    DLQFull { count: usize },
}

pub type S3Result<T> = Result<T, S3Error>;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURAÇÃO
// ═══════════════════════════════════════════════════════════════════════════

/// Configuração do S3 Connector
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Nome do bucket S3
    pub bucket: String,

    /// Prefixo das chaves (ex: "ledger/prod/")
    pub key_prefix: String,

    /// Storage class (STANDARD para 99.99% durability)
    pub storage_class: StorageClass,

    /// Habilita encriptação (AES256)
    pub encryption: bool,

    /// Número máximo de retries
    pub max_retries: u32,

    /// Timeout inicial para retry (ms)
    pub initial_retry_timeout_ms: u64,

    /// Tamanho máximo da Dead Letter Queue
    pub dlq_max_size: usize,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            bucket: std::env::var("BTV_S3_BUCKET")
                .unwrap_or_else(|_| "buildtovalue-ledger".to_string()),
            key_prefix: "ledger/".to_string(),
            storage_class: StorageClass::Standard,
            encryption: true,
            max_retries: 3,
            initial_retry_timeout_ms: 100,
            dlq_max_size: 1000,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// S3 CONNECTOR
// ═══════════════════════════════════════════════════════════════════════════

/// Connector para upload de LedgerEntry para S3
pub struct S3Connector {
    client: S3Client,
    config: S3Config,
    dlq: tokio::sync::Mutex<Vec<LedgerEntry>>,
}

impl S3Connector {
    /// Cria novo S3 Connector
    ///
    /// # Credentials
    /// Usa AWS SDK default credential chain:
    /// 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    /// 2. IAM Role (se rodando em EC2/ECS/Lambda)
    /// 3. ~/.aws/credentials
    pub async fn new(config: S3Config) -> S3Result<Self> {
        let aws_config = aws_config::load_from_env().await;
        let client = S3Client::new(&aws_config);

        Ok(Self {
            client,
            config,
            dlq: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    /// Upload de entry para S3 (com retry logic)
    ///
    /// # Key Format
    /// `{prefix}/{year}/{month}/{day}/{entry_id}.bin`
    ///
    /// Exemplo: `ledger/2026/02/05/00000001.bin`
    ///
    /// # Idempotência
    /// Mesmo entry_id sempre gera mesma chave S3.
    /// Reuploads sobrescrevem (S3 PutObject).
    ///
    /// # Retry Logic
    /// - 3 tentativas (configurável)
    /// - Backoff exponencial: 100ms, 200ms, 400ms
    /// - Após 3 falhas: move para Dead Letter Queue
    pub async fn upload(&self, entry: &LedgerEntry) -> S3Result<()> {
        let key = self.generate_key(entry);
        let body = self.serialize_entry(entry)?;

        let mut retries = 0;
        let mut backoff_ms = self.config.initial_retry_timeout_ms;

        loop {
            match self.upload_with_retry(&key, &body).await {
                Ok(_) => {
                    log::debug!("S3 upload successful: entry {}", entry.entry_id);
                    return Ok(());
                }
                Err(e) if retries < self.config.max_retries => {
                    retries += 1;
                    log::warn!(
                        "S3 upload failed (attempt {}/{}): {}",
                        retries,
                        self.config.max_retries,
                        e
                    );

                    // Exponential backoff
                    sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
                Err(e) => {
                    log::error!(
                        "S3 upload failed permanently after {} retries: {}",
                        retries,
                        e
                    );

                    // Move para Dead Letter Queue
                    self.push_to_dlq(*entry).await?;

                    return Err(S3Error::UploadFailed {
                        retries,
                        source: e,
                    });
                }
            }
        }
    }

    /// Upload interno (single attempt)
    async fn upload_with_retry(
        &self,
        key: &str,
        body: &[u8],
    ) -> Result<(), aws_sdk_s3::Error> {
        let mut request = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(ByteStream::from(body.to_vec()))
            .storage_class(self.config.storage_class.clone());

        if self.config.encryption {
            request = request.server_side_encryption(ServerSideEncryption::Aes256);
        }

        request.send().await?;

        Ok(())
    }

    /// Gera chave S3 a partir de entry
    ///
    /// Formato: `{prefix}/{year}/{month}/{day}/{entry_id:08x}.bin`
    fn generate_key(&self, entry: &LedgerEntry) -> String {
        use chrono::{DateTime, Utc};

        // Converte timestamp micros para DateTime
        let timestamp_secs = (entry.timestamp / 1_000_000) as i64;
        let dt = DateTime::<Utc>::from_timestamp(timestamp_secs, 0)
            .unwrap_or_else(|| Utc::now());

        format!(
            "{}{:04}/{:02}/{:02}/{:08x}.bin",
            self.config.key_prefix,
            dt.year(),
            dt.month(),
            dt.day(),
            entry.entry_id
        )
    }

    /// Serializa entry para bytes (bincode)
    fn serialize_entry(&self, entry: &LedgerEntry) -> S3Result<Vec<u8>> {
        bincode::serialize(entry).map_err(|e| S3Error::SerializationError(e.to_string()))
    }

    /// Adiciona entry à Dead Letter Queue
    async fn push_to_dlq(&self, entry: LedgerEntry) -> S3Result<()> {
        let mut dlq = self.dlq.lock().await;

        if dlq.len() >= self.config.dlq_max_size {
            return Err(S3Error::DLQFull { count: dlq.len() });
        }

        dlq.push(entry);

        log::warn!(
            "Entry {} moved to DLQ (size: {})",
            entry.entry_id,
            dlq.len()
        );

        Ok(())
    }

    /// Retorna entries na Dead Letter Queue
    pub async fn get_dlq(&self) -> Vec<LedgerEntry> {
        self.dlq.lock().await.clone()
    }

    /// Limpa Dead Letter Queue
    pub async fn clear_dlq(&self) {
        self.dlq.lock().await.clear();
    }

    /// Retenta upload de entries na DLQ
    pub async fn retry_dlq(&self) -> S3Result<usize> {
        let entries = {
            let mut dlq = self.dlq.lock().await;
            let entries = dlq.clone();
            dlq.clear();
            entries
        };

        let mut success_count = 0;

        for entry in entries {
            match self.upload(&entry).await {
                Ok(_) => success_count += 1,
                Err(e) => {
                    log::error!("DLQ retry failed for entry {}: {}", entry.entry_id, e);
                }
            }
        }

        log::info!("DLQ retry: {}/{} succeeded", success_count, entries.len());

        Ok(success_count)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let connector = S3Connector {
            client: todo!(),  // Mock
            config: S3Config {
                key_prefix: "ledger/".to_string(),
                ..Default::default()
            },
            dlq: tokio::sync::Mutex::new(Vec::new()),
        };

        let entry = LedgerEntry {
            entry_id: 42,
            timestamp: 1707178800000000, // 2026-02-05 12:00:00 UTC
            ..Default::default()
        };

        let key = connector.generate_key(&entry);

        assert_eq!(key, "ledger/2026/02/05/0000002a.bin");
    }

    #[tokio::test]
    #[ignore]  // Requer credenciais AWS reais
    async fn test_s3_upload_real() {
        let config = S3Config::default();
        let connector = S3Connector::new(config).await.unwrap();

        let entry = LedgerEntry {
            entry_id: 1,
            audit_trail_id: 0x1234,
            ..Default::default()
        };

        let result = connector.upload(&entry).await;

        assert!(result.is_ok());
    }
}
