//! Durable Ledger v2.3.2 — Sovereign Trust OS
//! Implementação corrigida para ADR-017.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::fs::OpenOptions;
use std::io::{Write, Read, Seek, SeekFrom};
use tokio::sync::mpsc;
use anyhow::{Result, Context};

use crate::ledger::entry::LedgerEntry;
use crate::ledger::wal::{WriteAheadLog as WalStore, WalConfig};
use crate::ledger::remote::{S3Config};
use crate::evidence::TechnicalEvidence;

pub struct DurableLedger {
    wal: WalStore,
    disk_path: PathBuf,
    disk_file: Arc<RwLock<std::fs::File>>,
    remote_tx: mpsc::UnboundedSender<LedgerEntry>,
    last_entry_id: Arc<RwLock<u64>>,
    last_entry_hash: Arc<RwLock<[u8; 32]>>,
}

impl DurableLedger {


    pub async fn new(_disk_path: PathBuf, _s3_config: S3Config) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&_disk_path)?;

        let (remote_tx, mut _remote_rx): (mpsc::UnboundedSender<LedgerEntry>, mpsc::UnboundedReceiver<LedgerEntry>) = mpsc::unbounded_channel();

        let wal_config = WalConfig {
            wal_path: _disk_path.with_extension("wal"),
            ..WalConfig::default()
        };

        let wal = WalStore::new(wal_config).context("Failed to init WAL")?;

        #[cfg(feature = "remote-sync")]
        {
            use crate::ledger::remote::sync::{RemoteSyncService, RemoteConfig, StorageType};
            use crate::ledger::wal::WalEntry; // se precisar converter

            // Cria um canal para o serviço de sincronia (espera WalEntry)
            let (service_tx, service_rx) = mpsc::channel(1000);

            let remote_config = RemoteConfig {
                storage_type: StorageType::S3,
                endpoint: _s3_config.endpoint.clone().unwrap_or_default(),
                bucket: _s3_config.bucket.clone(),
                prefix: _s3_config.key_prefix.clone(),
                batch_size: 100,
                max_retries: 3,
                enabled: true,
            };

            let service = RemoteSyncService::new(remote_config, service_rx);
            tokio::spawn(service.run());

            // Forward de LedgerEntry para WalEntry (conversão simplificada)
            tokio::spawn(async move {
                while let Some(entry) = _remote_rx.recv().await {
                    // Converte LedgerEntry para WalEntry (precisa de implementação)
                    // Por enquanto, enviamos um placeholder
                    let wal_entry = WalEntry {
                        seq: entry.entry_id,
                        timestamp: entry.timestamp,
                        evidence_snapshot: vec![], // TODO: serializar evidence
                    };
                    let _ = service_tx.send(wal_entry).await;
                }
            });
        }

        let (last_id, last_hash) = Self::load_last_state(&_disk_path)?;

        Ok(Self {
            wal,
            disk_path: _disk_path,
            disk_file: Arc::new(RwLock::new(file)),
            remote_tx,
            last_entry_id: Arc::new(RwLock::new(last_id)),
            last_entry_hash: Arc::new(RwLock::new(last_hash)),
        })
    }

    /// Adiciona uma nova entrada ao ledger e retorna o ID atribuído.
    pub fn append(&self, mut entry: LedgerEntry, evidence: &TechnicalEvidence) -> Result<u64> {
        let mut last_id = self.last_entry_id.write().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        *last_id += 1;
        entry.entry_id = *last_id;

        let last_hash = self.last_entry_hash.read().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        entry.previous_hash = *last_hash;

        entry.finalize();

        // Camada 1: WAL
        self.wal.append(evidence)?;

        // Camada 2: Disk
        self.write_to_disk(&entry)?;

        // Camada 3: Remote
        let _ = self.remote_tx.send(entry);

        let mut last_hash_write = self.last_entry_hash.write().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        *last_hash_write = entry.entry_hash;

        Ok(*last_id)
    }

    fn write_to_disk(&self, entry: &LedgerEntry) -> Result<()> {
        let mut file = self.disk_file.write().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        let bytes = bincode::serialize(entry)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn load_last_state(path: &PathBuf) -> Result<(u64, [u8; 32])> {
        if !path.exists() { return Ok((0, [0u8; 32])); }
        let mut file = std::fs::File::open(path)?;
        let size = file.metadata()?.len();
        if size < 384 { return Ok((0, [0u8; 32])); }

        file.seek(SeekFrom::End(-384))?;
        let mut buffer = [0u8; 384];
        file.read_exact(&mut buffer)?;
        let entry: LedgerEntry = bincode::deserialize(&buffer)?;
        Ok((entry.entry_id, entry.entry_hash))
    }
}