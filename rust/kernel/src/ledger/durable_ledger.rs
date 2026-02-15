//! Durable Ledger v2.5.0 — Sovereign Trust OS
//! F1.5-04: Recovery < 5s + Chain Integrity Verification

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::fs::OpenOptions;
use std::io::{Write, Read, Seek, SeekFrom, BufReader};
use tokio::sync::mpsc;
use anyhow::{Result, Context};

use crate::ledger::entry::LedgerEntry;
use crate::ledger::wal::{WriteAheadLog as WalStore, WalConfig, WalEntry};
use crate::ledger::remote::S3Config;
use crate::evidence::TechnicalEvidence;

// ---------------------------------------------------------------------
// CHAIN STATUS
// ---------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Chain is valid
    Valid { entry_count: u64 },
    /// Empty ledger (no entries)
    Empty,
    /// Hash mismatch at specific entry
    TamperedAt { entry_id: u64, expected_hash: [u8; 32], actual_hash: [u8; 32] },
    /// Chain link broken (previous_hash mismatch)
    BrokenAt { entry_id: u64 },
    /// Deserialization error at offset
    CorruptAt { byte_offset: u64 },
}

// ---------------------------------------------------------------------
// RECOVERY RESULT
// ---------------------------------------------------------------------
#[derive(Debug)]
pub struct RecoveryResult {
    pub entries_from_disk: u64,
    pub entries_from_wal: u64,
    pub recovery_time_ms: f64,
    pub chain_status: ChainStatus,
}

// ---------------------------------------------------------------------
// DURABLE LEDGER
// ---------------------------------------------------------------------
pub struct DurableLedger {
    wal: WalStore,
    disk_path: PathBuf,
    disk_file: Arc<RwLock<std::fs::File>>,
    remote_tx: mpsc::UnboundedSender<LedgerEntry>,
    last_entry_id: Arc<RwLock<u64>>,
    last_entry_hash: Arc<RwLock<[u8; 32]>>,
}

impl DurableLedger {
    pub async fn new(disk_path: PathBuf, s3_config: S3Config) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&disk_path)?;

        let (remote_tx, mut _remote_rx): (
            mpsc::UnboundedSender<LedgerEntry>,
            mpsc::UnboundedReceiver<LedgerEntry>,
        ) = mpsc::unbounded_channel();

        let wal_config = WalConfig {
            wal_path: disk_path.with_extension("wal"),
            ..WalConfig::default()
        };

        let wal = WalStore::new(wal_config).context("Failed to init WAL")?;

        #[cfg(feature = "remote-sync")]
        {
            use crate::ledger::remote::sync::{RemoteSyncService, RemoteConfig, StorageType};

            let (service_tx, service_rx) = mpsc::channel(1000);

            let remote_config = RemoteConfig {
                storage_type: StorageType::S3,
                endpoint: s3_config.endpoint.clone().unwrap_or_default(),
                bucket: s3_config.bucket.clone(),
                prefix: s3_config.key_prefix.clone(),
                batch_size: 100,
                max_retries: 3,
                enabled: true,
            };

            let service = RemoteSyncService::new(remote_config, service_rx);
            tokio::spawn(service.run());

            tokio::spawn(async move {
                while let Some(entry) = _remote_rx.recv().await {
                    let wal_entry = WalEntry {
                        seq: entry.entry_id,
                        timestamp: entry.timestamp,
                        evidence_snapshot: vec![],
                    };
                    let _ = service_tx.send(wal_entry).await;
                }
            });
        }

        let (last_id, last_hash) = Self::load_last_state(&disk_path)?;

        Ok(Self {
            wal,
            disk_path,
            disk_file: Arc::new(RwLock::new(file)),
            remote_tx,
            last_entry_id: Arc::new(RwLock::new(last_id)),
            last_entry_hash: Arc::new(RwLock::new(last_hash)),
        })
    }

    // -----------------------------------------------------------------
    // APPEND
    // -----------------------------------------------------------------

    pub fn append(&self, mut entry: LedgerEntry, evidence: &TechnicalEvidence) -> Result<u64> {
        let mut last_id = self.last_entry_id.write()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        *last_id += 1;
        entry.entry_id = *last_id;

        let last_hash = self.last_entry_hash.read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        entry.previous_hash = *last_hash;

        entry.finalize();

        // Camada 1: WAL (fail-secure: se WAL falha, não persiste)
        self.wal.append(evidence)?;

        // Camada 2: Disk
        self.write_to_disk(&entry)?;

        // Camada 3: Remote (best-effort)
        let _ = self.remote_tx.send(entry);

        let mut last_hash_write = self.last_entry_hash.write()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        *last_hash_write = entry.entry_hash;

        Ok(*last_id)
    }

    // -----------------------------------------------------------------
    // RECOVERY (F1.5-04)
    // -----------------------------------------------------------------

    /// Recover ledger from disk + WAL after crash.
    /// Target: < 5s for 10k entries.
    pub fn recover(disk_path: &PathBuf) -> Result<RecoveryResult> {
        let start = std::time::Instant::now();

        // 1. Read all entries from disk
        let disk_entries = Self::read_all_entries_from_disk(disk_path)?;
        let entries_from_disk = disk_entries.len() as u64;

        // 2. Read WAL entries (evidence snapshots not yet on disk)
        let wal_path = disk_path.with_extension("wal");
        let entries_from_wal = if wal_path.exists() {
            Self::count_wal_entries(&wal_path)?
        } else {
            0
        };

        // 3. Reconstruct last state
        let (last_id, last_hash) = if let Some(last) = disk_entries.last() {
            (last.entry_id, last.entry_hash)
        } else {
            (0, [0u8; 32])
        };

        // 4. Verify chain integrity
        let chain_status = Self::verify_chain_from_entries(&disk_entries);

        let recovery_time_ms = start.elapsed().as_secs_f64() * 1000.0;

        log::info!(
            "Ledger recovery: {} disk entries, {} WAL entries, {:.2}ms",
            entries_from_disk, entries_from_wal, recovery_time_ms
        );

        if recovery_time_ms > 5000.0 {
            log::warn!(
                "Recovery exceeded 5s SLA: {:.2}ms ({} entries)",
                recovery_time_ms, entries_from_disk
            );
        }

        Ok(RecoveryResult {
            entries_from_disk,
            entries_from_wal,
            recovery_time_ms,
            chain_status,
        })
    }

    /// Read all LedgerEntry from disk file sequentially.
    fn read_all_entries_from_disk(path: &PathBuf) -> Result<Vec<LedgerEntry>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let data = std::fs::read(path)?;
        let mut entries = Vec::new();
        let mut offset = 0usize;

        while offset < data.len() {
            match bincode::deserialize::<LedgerEntry>(&data[offset..]) {
                Ok(entry) => {
                    let serialized_size = bincode::serialized_size(&entry)
                        .context("Failed to compute entry size")? as usize;
                    entries.push(entry);
                    offset += serialized_size;
                }
                Err(_) => {
                    log::warn!("Corrupt entry at offset {}, stopping recovery", offset);
                    break;
                }
            }
        }

        Ok(entries)
    }

    /// Count WAL entries without full deserialization of evidence.
    fn count_wal_entries(wal_path: &PathBuf) -> Result<u64> {
        let mut file = std::fs::File::open(wal_path)?;
        let file_size = file.metadata()?.len();
        let mut count = 0u64;
        let mut pos = 0u64;

        while pos < file_size {
            // Read length prefix (u32)
            let mut len_bytes = [0u8; 4];
            if file.read_exact(&mut len_bytes).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_bytes) as u64;

            // Skip payload
            if file.seek(SeekFrom::Current(len as i64)).is_err() {
                break;
            }

            count += 1;
            pos += 4 + len;
        }

        Ok(count)
    }

    // -----------------------------------------------------------------
    // CHAIN INTEGRITY VERIFICATION (F1.5-04)
    // -----------------------------------------------------------------

    /// Verify entire chain integrity from disk.
    /// Returns ChainStatus with detail on any failure.
    pub fn verify_chain_integrity(disk_path: &PathBuf) -> Result<ChainStatus> {
        let entries = Self::read_all_entries_from_disk(disk_path)?;
        Ok(Self::verify_chain_from_entries(&entries))
    }

    /// Verify chain from a Vec of entries (used by both recovery and standalone).
    fn verify_chain_from_entries(entries: &[LedgerEntry]) -> ChainStatus {
        if entries.is_empty() {
            return ChainStatus::Empty;
        }

        let mut previous_hash: Option<[u8; 32]> = None;

        for entry in entries {
            // 1. Verify entry self-hash
            if !entry.validate() {
                return ChainStatus::TamperedAt {
                    entry_id: entry.entry_id,
                    expected_hash: entry.entry_hash,
                    actual_hash: entry.calculate_hash(),
                };
            }

            // 2. Verify chain link (previous_hash must match)
            if let Some(prev) = previous_hash {
                if entry.previous_hash != prev {
                    return ChainStatus::BrokenAt {
                        entry_id: entry.entry_id,
                    };
                }
            }

            previous_hash = Some(entry.entry_hash);
        }

        ChainStatus::Valid {
            entry_count: entries.len() as u64,
        }
    }

    // -----------------------------------------------------------------
    // INTERNAL
    // -----------------------------------------------------------------

    fn write_to_disk(&self, entry: &LedgerEntry) -> Result<()> {
        let mut file = self.disk_file.write()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        let bytes = bincode::serialize(entry)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn load_last_state(path: &PathBuf) -> Result<(u64, [u8; 32])> {
        if !path.exists() {
            return Ok((0, [0u8; 32]));
        }
        let mut file = std::fs::File::open(path)?;
        let size = file.metadata()?.len();
        if size < 384 {
            return Ok((0, [0u8; 32]));
        }

        file.seek(SeekFrom::End(-384))?;
        let mut buffer = [0u8; 384];
        file.read_exact(&mut buffer)?;
        let entry: LedgerEntry = bincode::deserialize(&buffer)?;
        Ok((entry.entry_id, entry.entry_hash))
    }

    pub fn flush(&self) -> Result<()> {
        self.wal.flush()
    }

    pub fn get_last_entry_id(&self) -> u64 {
        *self.last_entry_id.read().unwrap_or(RwLock::new(0).read().unwrap())
    }
}