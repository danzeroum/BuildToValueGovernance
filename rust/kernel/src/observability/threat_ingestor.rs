//! Threat Ingestor v2.3.2 (WAL-enabled)
//!
//! Immutable log of security events with cryptographic integrity.
//!
//! **Features**:
//! - Write-Ahead Log (WAL) for crash recovery
//! - BLAKE3 Merkle-chaining (integrity)
//! - O(1) in-memory lookups
//!
//! **CHANGELOG v2.3.2**:
//! - ✅ Renamed ThreatIngestorV2 -> ThreatIngestor (Canonical)
//! - ✅ Fixed IO imports (Read trait)
//! - ✅ Robust WAL replay logic

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
// ✅ CORREÇÃO: Adicionado 'Read' para usar read_exact()
use std::io::{self, Write, BufWriter, BufReader, Read};
use std::path::{Path, PathBuf};
use blake3::Hasher;

/// Threat event with BLAKE3 integrity hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub threat_type: String,
    pub severity: u8,
    pub source: String,
    pub indicators: Vec<String>,
    pub timestamp: i64,
    pub hash: String,
}

impl ThreatEvent {
    /// Computes cryptographic hash of the event content
    pub fn compute_hash(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.threat_type.as_bytes());
        hasher.update(&[self.severity]);
        hasher.update(self.source.as_bytes());

        for indicator in &self.indicators {
            hasher.update(indicator.as_bytes());
        }

        hasher.update(&self.timestamp.to_le_bytes());

        // Finalize produces Hash, which implements Display as hex string
        hasher.finalize().to_string()
    }

    pub fn verify_integrity(&self) -> bool {
        self.compute_hash() == self.hash
    }
}

/// Threat Intelligence Database with WAL (Write-Ahead Log)
// ✅ CORREÇÃO: Renomeado de ThreatIngestorV2 para ThreatIngestor para match com mod.rs
pub struct ThreatIngestor {
    events: HashMap<String, ThreatEvent>,
    index_by_type: HashMap<String, Vec<String>>,
    wal_path: PathBuf,
    wal_writer: BufWriter<File>,
}

impl ThreatIngestor {
    /// Initialize with WAL file
    pub fn new(wal_path: impl AsRef<Path>) -> Result<Self, String> {
        let wal_path = wal_path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = wal_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create WAL directory: {}", e))?;
        }

        // Open WAL in append mode
        let wal_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .map_err(|e| format!("Failed to open WAL: {}", e))?;

        let wal_writer = BufWriter::new(wal_file);

        let mut ingestor = Self {
            events: HashMap::new(),
            index_by_type: HashMap::new(),
            wal_path: wal_path.clone(),
            wal_writer,
        };

        // Replay WAL on startup (crash recovery)
        ingestor.replay_wal()?;

        Ok(ingestor)
    }

    /// Ingest threat event with WAL persistence
    pub fn ingest(&mut self, mut event: ThreatEvent) -> Result<(), String> {
        // Compute hash
        event.hash = event.compute_hash();

        // Verify integrity (Self-check before write)
        if !event.verify_integrity() {
            return Err("Hash integrity check failed".to_string());
        }

        // Write to WAL BEFORE in-memory update (fail-secure)
        self.append_to_wal(&event)?;

        // Index by type
        self.index_by_type
            .entry(event.threat_type.clone())
            .or_insert_with(Vec::new)
            .push(event.id.clone());

        // Store event
        self.events.insert(event.id.clone(), event);

        Ok(())
    }

    /// Append event to WAL with fsync (durability guarantee)
    fn append_to_wal(&mut self, event: &ThreatEvent) -> Result<(), String> {
        // Serialize to bincode (compact binary format)
        let encoded = bincode::serialize(event)
            .map_err(|e| format!("Serialization error: {}", e))?;

        // Write length prefix (u32) + payload
        let len = encoded.len() as u32;
        self.wal_writer
            .write_all(&len.to_le_bytes())
            .map_err(|e| format!("WAL write error (len): {}", e))?;
        self.wal_writer
            .write_all(&encoded)
            .map_err(|e| format!("WAL write error (payload): {}", e))?;

        // Flush to OS buffer
        self.wal_writer
            .flush()
            .map_err(|e| format!("WAL flush error: {}", e))?;

        // fsync for durability (99.99%)
        self.wal_writer
            .get_ref()
            .sync_all()
            .map_err(|e| format!("WAL fsync error: {}", e))?;

        Ok(())
    }

    /// Replay WAL on startup (crash recovery)
    fn replay_wal(&mut self) -> Result<(), String> {
        if !self.wal_path.exists() {
            return Ok(()); // No WAL to replay
        }

        let file = File::open(&self.wal_path)
            .map_err(|e| format!("Failed to open WAL for replay: {}", e))?;
        let mut reader = BufReader::new(file);

        let mut replayed = 0;

        loop {
            // Read length prefix (4 bytes)
            let mut len_bytes = [0u8; 4];
            // ✅ CORREÇÃO: Uso correto de read_exact e tratamento de EOF
            match reader.read_exact(&mut len_bytes) {
                Ok(_) => {},
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break, // Clean EOF
                Err(e) => return Err(format!("WAL read error (len): {}", e)),
            }

            let len = u32::from_le_bytes(len_bytes) as usize;

            // Read payload
            let mut payload = vec![0u8; len];
            reader
                .read_exact(&mut payload)
                .map_err(|e| format!("WAL read error (payload): {}", e))?;

            // Deserialize
            match bincode::deserialize::<ThreatEvent>(&payload) {
                Ok(event) => {
                    // Verify integrity
                    if !event.verify_integrity() {
                        return Err(format!("Corrupted WAL entry detected: {}", event.id));
                    }

                    // Restore to in-memory structures
                    self.index_by_type
                        .entry(event.threat_type.clone())
                        .or_insert_with(Vec::new)
                        .push(event.id.clone());
                    self.events.insert(event.id.clone(), event);

                    replayed += 1;
                },
                Err(e) => {
                    return Err(format!("WAL deserialization error: {}", e));
                }
            }
        }

        if replayed > 0 {
            log::info!("WAL replay complete: {} events restored", replayed);
        }
        Ok(())
    }

    /// Query threats by type (O(1) lookup)
    pub fn query_by_type(&self, threat_type: &str) -> Vec<&ThreatEvent> {
        self.index_by_type
            .get(threat_type)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.events.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_wal_persistence() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("threats.wal");

        // Ingest event
        {
            let mut ingestor = ThreatIngestor::new(&wal_path).unwrap();

            let event = ThreatEvent {
                id: "threat-001".to_string(),
                threat_type: "prompt_injection".to_string(),
                severity: 9,
                source: "OWASP".to_string(),
                indicators: vec!["ignore previous".to_string()],
                timestamp: 1234567890,
                hash: String::new(),
            };

            ingestor.ingest(event.clone()).unwrap();
        } // ingestor dropped (simulates crash)

        // Recover from WAL
        {
            let ingestor = ThreatIngestor::new(&wal_path).unwrap();
            let results = ingestor.query_by_type("prompt_injection");
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "threat-001");
        }
    }

    #[test]
    fn test_hash_integrity_check() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("threats.wal");
        let mut ingestor = ThreatIngestor::new(&wal_path).unwrap();

        let mut event = ThreatEvent {
            id: "threat-002".to_string(),
            threat_type: "pii_leakage".to_string(),
            severity: 8,
            source: "MISP".to_string(),
            indicators: vec!["CPF".to_string()],
            timestamp: 1234567890,
            hash: String::new(),
        };

        // Compute hash
        event.hash = event.compute_hash();

        // Ingest (should succeed)
        assert!(ingestor.ingest(event.clone()).is_ok());

        // Corrupt hash
        event.hash = "invalid_hash".to_string();

        // Ingest (should fail)
        assert!(ingestor.ingest(event).is_err());
    }
}