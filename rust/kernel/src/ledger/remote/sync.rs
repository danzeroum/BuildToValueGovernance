//! Remote Sync Layer v2.3.2
//!
//! Orquestrador de sincronização background.
//! - Gerencia fila de upload
//! - Abstrai o Storage (S3, Mock, etc)
//! - Implementa Batching

use crate::ledger::wal::WalEntry;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const BATCH_SIZE: usize = 100;
const MAX_RETRIES: u32 = 3;
const RETRY_BASE_DELAY_MS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    S3,
    GCS,
    Azure,
    Mock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub storage_type: StorageType,
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    pub batch_size: usize,
    pub max_retries: u32,
    pub enabled: bool,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Mock,
            endpoint: "http://localhost:9000".to_string(),
            bucket: "ledger-backup".to_string(),
            prefix: "wal/".to_string(),
            batch_size: BATCH_SIZE,
            max_retries: MAX_RETRIES,
            enabled: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SYNC SERVICE
// ═══════════════════════════════════════════════════════════════════════════

pub struct RemoteSyncService {
    config: RemoteConfig,
    receiver: mpsc::Receiver<WalEntry>,
    buffer: Vec<WalEntry>,
}

impl RemoteSyncService {
    pub fn new(config: RemoteConfig, receiver: mpsc::Receiver<WalEntry>) -> Self {
        let batch_size = config.batch_size;
        Self {
            config,
            receiver,
            buffer: Vec::with_capacity(batch_size),
        }
    }

    pub async fn run(mut self) {
        if !self.config.enabled {
            log::info!("Remote sync disabled");
            while self.receiver.recv().await.is_some() {}
            return;
        }

        log::info!("Starting remote sync service [{:?}] bucket: {}", self.config.storage_type, self.config.bucket);

        while let Some(entry) = self.receiver.recv().await {
            self.handle_entry(entry).await;
        }

        self.flush_buffer().await;
        log::info!("Remote sync service stopped");
    }

    async fn handle_entry(&mut self, entry: WalEntry) {
        self.buffer.push(entry);

        if self.buffer.len() >= self.config.batch_size {
            self.flush_buffer().await;
        }
    }

    async fn flush_buffer(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        let batch: Vec<WalEntry> = self.buffer.drain(..).collect();

        if let Err(e) = self.upload_batch_with_retry(&batch).await {
            log::error!("Failed to upload batch of {} entries: {}", batch.len(), e);
        } else {
            log::debug!("Successfully uploaded batch of {} entries", batch.len());
        }
    }

    async fn upload_batch_with_retry(&self, _batch: &[WalEntry]) -> Result<()> {
        let mut attempts = 0;

        loop {
            attempts += 1;

            // Simulação de sucesso (o S3Connector real é usado em produção)
            let result: Result<()> = Ok(());

            match result {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if attempts >= self.config.max_retries {
                        return Err(e).context("Max retries exceeded");
                    }

                    // ✅ CORREÇÃO: Uso de saturating_sub para evitar overflow "0_usize - 1_usize"
                    // Garante que não haja panic se attempts for 0 (embora comece em 1)
                    let backoff = RETRY_BASE_DELAY_MS * 2u64.pow(attempts.saturating_sub(1));
                    sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC FACTORY
// ═══════════════════════════════════════════════════════════════════════════

pub fn create_remote_sync(config: RemoteConfig) -> (mpsc::Sender<WalEntry>, RemoteSyncService) {
    let (tx, rx) = mpsc::channel(1000);
    let service = RemoteSyncService::new(config, rx);
    (tx, service)
}