//! Write-Ahead Log (WAL) v2.3.2
//! Durabilidade imediata com fsync.
use anyhow::{Result, Context};
use crate::evidence::TechnicalEvidence;
use crate::core::types::EVIDENCE_SIZE;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone)]
pub struct WalConfig {
    pub wal_path: PathBuf,
    pub fsync_enabled: bool,
    pub max_size_bytes: u64,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            wal_path: PathBuf::from("ledger.wal"),
            fsync_enabled: true,
            max_size_bytes: 100 * 1024 * 1024,
        }
    }
}

/// Entrada do WAL (serializada)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    pub seq: u64,
    pub timestamp: u128,
    pub evidence_snapshot: Vec<u8>,
}

impl WalEntry {
    pub fn from_evidence(seq: u64, evidence: &TechnicalEvidence) -> Self {
        Self {
            seq,
            timestamp: evidence.timestamp,
            evidence_snapshot: evidence.to_bytes().to_vec(),
        }
    }

    pub fn append(seq: u64, evidence: &TechnicalEvidence) -> Result<Self> {
        Ok(Self::from_evidence(seq, evidence))
    }

    pub fn restore_evidence(&self) -> Option<TechnicalEvidence> {
        if self.evidence_snapshot.len() == EVIDENCE_SIZE {
            let mut arr = [0u8; EVIDENCE_SIZE];
            arr.copy_from_slice(&self.evidence_snapshot);
            TechnicalEvidence::from_bytes(&arr)
        } else {
            None
        }
    }
}

pub struct WriteAheadLog {
    file: Mutex<BufWriter<File>>,
    pub config: WalConfig,
    current_seq: Mutex<u64>,
}

impl WriteAheadLog {
    pub fn new(config: WalConfig) -> Result<Self> {
        if let Some(parent) = config.wal_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create WAL directory")?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.wal_path)
            .with_context(|| format!("Failed to open WAL at {:?}", config.wal_path))?;
        Ok(Self {
            file: Mutex::new(BufWriter::new(file)),
            config,
            current_seq: Mutex::new(0),
        })
    }

    pub fn append(&self, evidence: &TechnicalEvidence) -> Result<u64> {
        let mut seq_guard = self.current_seq.lock().unwrap();
        *seq_guard += 1;
        let seq = *seq_guard;

        let entry = WalEntry::from_evidence(seq, evidence);
        let bytes = bincode::serialize(&entry).context("Failed to serialize WAL entry")?;

        let mut file_guard = self.file.lock().unwrap();
        file_guard.write_all(&(bytes.len() as u32).to_le_bytes())?;
        file_guard.write_all(&bytes)?;

        if self.config.fsync_enabled {
            file_guard.flush()?;
            file_guard.get_ref().sync_all()?;
        }
        Ok(seq)
    }

    pub fn flush(&self) -> Result<()> {
        let mut file_guard = self.file.lock().unwrap();
        file_guard.flush()?;
        file_guard.get_ref().sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use super::*;


    #[test]
    fn test_wal_write_and_flush() {
        let temp = NamedTempFile::new().unwrap();
        let config = WalConfig {
            wal_path: temp.path().to_path_buf(),
            fsync_enabled: false,
            ..Default::default()
        };
        let wal = WriteAheadLog::new(config).unwrap();
        let evidence = TechnicalEvidence::new(123);
        let seq = wal.append(&evidence).unwrap();
        assert_eq!(seq, 1);
        wal.flush().unwrap();
        assert!(temp.path().metadata().unwrap().len() > 0);
    }

    #[test]
    fn test_wal_entry_restore() {
        let evidence = TechnicalEvidence::new(999);
        let entry = WalEntry::from_evidence(1, &evidence);
        assert_eq!(entry.evidence_snapshot.len(), EVIDENCE_SIZE);
        let restored = entry.restore_evidence().unwrap();
        assert_eq!(restored.audit_trail_id, 999);
    }
}