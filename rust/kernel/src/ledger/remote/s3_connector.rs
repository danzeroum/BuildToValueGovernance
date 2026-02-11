//! S3 Remote Sync Connector v2.3.2
//!
//! Implementação concreta do upload para S3 com:
//! - Retry automático (Exponential Backoff)
//! - Dead Letter Queue (DLQ) em memória
//! - Mapeamento de LedgerEntry para Objetos S3
//!
//! **CHANGELOG v2.3.2**:
//! - ✅ Correção de Overflow Aritmético (attempts - 1)
//! - ✅ Estrutura de erros robusta (thiserror)

use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ServerSideEncryption, StorageClass};
use std::time::{SystemTime, Duration};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::ledger::entry::LedgerEntry;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIG & ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Error, Debug)]
pub enum S3Error {
    #[error("S3 upload failed after {retries} retries: {source}")]
    UploadFailed {
        retries: u32,
        #[source]
        source: aws_sdk_s3::Error, // Erro genérico do SDK wrapper
    },

    #[error("S3 configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket: String,
    pub key_prefix: String,
    pub region: String,
    pub endpoint: Option<String>, // Para LocalStack/MinIO
    pub force_path_style: bool,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            bucket: "buildtovalue-ledger".to_string(),
            key_prefix: "wal/".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            force_path_style: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// S3 CONNECTOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct S3Connector {
    client: S3Client,
    config: S3Config,
    // Buffer simples para falhas (em produção seria persistente/disk-backed)
    dlq: Mutex<Vec<LedgerEntry>>,
}

impl S3Connector {
    /// Cria novo conector S3
    pub async fn new(config: S3Config) -> Result<Self, S3Error> {
        let aws_config = aws_config::load_from_env().await;

        // Builder para custom endpoint (MinIO/LocalStack)
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

        // Serialização (usando Bincode ou JSON)
        // Aqui assumimos bincode para consistência com WAL
        let body_bytes = bincode::serialize(entry)
            .map_err(|e| S3Error::SerializationError(e.to_string()))?;

        let body = ByteStream::from(body_bytes);

        let mut attempts = 0;
        let max_retries = 3;

        loop {
            attempts += 1;

            // Clonamos o body para retry (ByteStream de Vec é barato/clonável na memória)
            let body_clone = body.try_clone().expect("In-memory ByteStream clone failed");

            let result = self.client.put_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .body(body_clone)
                .server_side_encryption(ServerSideEncryption::Aes256)
                .storage_class(StorageClass::Standard)
                .send()
                .await;

            match result {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if attempts >= max_retries {
                        // Salva na DLQ antes de retornar erro
                        let mut dlq = self.dlq.lock().await;
                        dlq.push(*entry); // LedgerEntry é Copy

                        return Err(S3Error::UploadFailed {
                            retries: attempts,
                            source: e.into(), // Converte SdkError para Error genérico
                        });
                    }

                    // ✅ CORREÇÃO: Uso de saturating_sub para evitar overflow "0_usize - 1_usize"
                    // Evita panic se a lógica de attempts for alterada ou inferida como usize
                    let backoff_exponent = attempts.saturating_sub(1);
                    let delay = 100 * 2_u64.pow(backoff_exponent);

                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }

    /// Gera chave S3 baseada em data/hora para particionamento eficiente
    /// Formato: prefix/YYYY/MM/DD/entry_id.bin
    fn generate_key(&self, entry: &LedgerEntry) -> String {
        use chrono::{DateTime, Utc};
        // Conversão timestamp (micros) -> Data
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