//! Durable Ledger v2.5.1 — Sovereign Trust OS
//! F1.5-04: Recovery < 5s + Chain Integrity Verification
//! Wire 5 (PROP-005): SessionAggregator integrado ao append() (Fourth Estate).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::fs::OpenOptions;
use std::io::{Write, Read, Seek, SeekFrom};
use tokio::sync::mpsc;
use anyhow::{Result, Context};

use crate::ledger::entry::LedgerEntry;
use crate::ledger::wal::{WriteAheadLog as WalStore, WalConfig};
use crate::ledger::remote::S3Config;
use crate::ledger::session_agg::{SessionAggregator, SessionAggregate, SessionEvent}; // Wire 5
use crate::core::types::RiskLevel; // Wire 5
use crate::evidence::TechnicalEvidence;

// ---------------------------------------------------------------------
// CHAIN STATUS
// ---------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    Valid { entry_count: u64 },
    Empty,
    TamperedAt { entry_id: u64, expected_hash: [u8; 32], actual_hash: [u8; 32] },
    BrokenAt { entry_id: u64 },
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
    _disk_path: PathBuf,
    disk_file: Arc<RwLock<std::fs::File>>,
    remote_tx: mpsc::UnboundedSender<LedgerEntry>,
    last_entry_id: Arc<RwLock<u64>>,
    last_entry_hash: Arc<RwLock<[u8; 32]>>,
    session_agg: Mutex<SessionAggregator>, // Wire 5: PROP-005 Fourth Estate
}

impl DurableLedger {
    pub async fn new(disk_path: PathBuf, _s3_config: S3Config) -> Result<Self> {
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
            use crate::ledger::wal::WalEntry;

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
            _disk_path: disk_path,
            disk_file: Arc::new(RwLock::new(file)),
            remote_tx,
            last_entry_id: Arc::new(RwLock::new(last_id)),
            last_entry_hash: Arc::new(RwLock::new(last_hash)),
            session_agg: Mutex::new(SessionAggregator::new(0)),
        })
    }

    // -----------------------------------------------------------------
    // APPEND
    // -----------------------------------------------------------------

    pub fn append(&self, mut entry: LedgerEntry, evidence: &TechnicalEvidence) -> Result<u64> {
        self.append_internal(&mut entry, evidence, None)
    }

    /// Append com assinatura HMAC do operador (ADR-0083: TEK por tenant).
    /// O `signing_key` é injetado em `finalize_with_key` ao invés do default
    /// zero-key, garantindo que o `verdict_id` seja verificável apenas com a
    /// chave do tenant correspondente.
    pub fn append_with_key(
        &self,
        mut entry: LedgerEntry,
        evidence: &TechnicalEvidence,
        signing_key: &[u8],
    ) -> Result<u64> {
        self.append_internal(&mut entry, evidence, Some(signing_key))
    }

    fn append_internal(
        &self,
        entry: &mut LedgerEntry,
        evidence: &TechnicalEvidence,
        signing_key: Option<&[u8]>,
    ) -> Result<u64> {
        let mut last_id = self.last_entry_id.write()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        *last_id += 1;
        entry.entry_id = *last_id;

        let last_hash = self.last_entry_hash.read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        entry.previous_hash = *last_hash;

        // INVARIANTE: `signing_key = None` preserva o comportamento legado
        // de `append()` byte-a-byte — `entry.finalize()` usa zero-key por
        // spec (ver `LedgerEntry::finalize` em entry.rs). Caller pré-ADR-0083
        // (ex: ffi/bridge/mod.rs) continua produzindo verdict_id verificável
        // com a mesma chave-zero, mantendo a cadeia de auditoria existente.
        match signing_key {
            Some(key) => entry.finalize_with_key(key),
            None => entry.finalize(),
        }

        self.wal.append(evidence)?;
        self.write_to_disk(entry)?;
        let _ = self.remote_tx.send(*entry);

        let mut last_hash_write = self.last_entry_hash.write()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        *last_hash_write = entry.entry_hash;

        // ── Wire 5: PROP-005 Session Aggregator — Fourth Estate ────────────
        // Fail-safe: lock poison → skip (append já foi persistido com sucesso).
        let risk_level = match evidence.composite_risk as u32 {
            0..=29  => RiskLevel::Safe,
            30..=59 => RiskLevel::Low,
            60..=79 => RiskLevel::High,
            _       => RiskLevel::Critical,
        };
        let session_event = SessionEvent::new(
            evidence.timestamp as u64,
            risk_level,
            evidence.composite_risk,
            evidence.critical_count > 0,
            evidence.critical_count > 0,
        );
        if let Ok(mut agg) = self.session_agg.lock() {
            agg.push(session_event);
        } else {
            log::warn!("PROP-005: session_agg lock poisoned — evento descartado, entry_id={}", *last_id);
        }

        Ok(*last_id)
    }

    // -----------------------------------------------------------------
    // SESSION AGGREGATE (PROP-005 / Fourth Estate)
    // -----------------------------------------------------------------

    pub fn get_session_aggregate(&self) -> Option<SessionAggregate> {
        self.session_agg.lock().ok().map(|agg| agg.aggregate())
    }

    // -----------------------------------------------------------------
    // RECOVERY (F1.5-04)
    // -----------------------------------------------------------------

    pub fn recover(disk_path: &PathBuf) -> Result<RecoveryResult> {
        let start = std::time::Instant::now();

        let disk_entries = Self::read_all_entries_from_disk(disk_path)?;
        let entries_from_disk = disk_entries.len() as u64;

        let wal_path = disk_path.with_extension("wal");
        let entries_from_wal = if wal_path.exists() {
            Self::count_wal_entries(&wal_path)?
        } else {
            0
        };

        let (_last_id, _last_hash) = if let Some(last) = disk_entries.last() {
            (last.entry_id, last.entry_hash)
        } else {
            (0, [0u8; 32])
        };

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

    fn count_wal_entries(wal_path: &PathBuf) -> Result<u64> {
        let mut file = std::fs::File::open(wal_path)?;
        let file_size = file.metadata()?.len();
        let mut count = 0u64;
        let mut pos = 0u64;

        while pos < file_size {
            let mut len_bytes = [0u8; 4];
            if file.read_exact(&mut len_bytes).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_bytes) as u64;

            if file.seek(SeekFrom::Current(len as i64)).is_err() {
                break;
            }

            count += 1;
            pos += 4 + len;
        }

        Ok(count)
    }

    // -----------------------------------------------------------------
    // CHAIN INTEGRITY VERIFICATION
    // -----------------------------------------------------------------

    pub fn verify_chain_integrity(disk_path: &PathBuf) -> Result<ChainStatus> {
        let entries = Self::read_all_entries_from_disk(disk_path)?;
        Ok(Self::verify_chain_from_entries(&entries))
    }

    fn verify_chain_from_entries(entries: &[LedgerEntry]) -> ChainStatus {
        if entries.is_empty() {
            return ChainStatus::Empty;
        }

        let mut previous_hash: Option<[u8; 32]> = None;

        for entry in entries {
            if !entry.validate() {
                return ChainStatus::TamperedAt {
                    entry_id: entry.entry_id,
                    expected_hash: entry.entry_hash,
                    actual_hash: entry.calculate_hash(),
                };
            }

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
        *self.last_entry_id.read()
            .unwrap_or_else(|e| panic!("BTV invariant violation: Ledger lock poisoned: {e}"))
    }
}
