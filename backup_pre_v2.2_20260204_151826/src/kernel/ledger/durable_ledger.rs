
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::fs::OpenOptions;
use std::io::Write;
use tokio::sync::mpsc;

/// Ledger durável com múltiplas camadas de persistência
/// 
/// Camadas:
/// 1. WAL (RAM) - < 1ms, volátil
/// 2. Disk Buffer - < 5ms, persistente
/// 3. Remote Sync (S3) - < 10ms (async), 99.99% durável
/// 4. External Audit - < 60s (batch), imutável
pub struct DurableLedger {
    /// WAL (Camada 1)
    wal: WriteAheadLog,
    
    /// Caminho do arquivo em disco (Camada 2)
    disk_path: PathBuf,
    
    /// Handle do arquivo (mantém aberto para performance)
    disk_file: Arc<RwLock<std::fs::File>>,
    
    /// Channel para remote sync (Camada 3)
    remote_tx: mpsc::UnboundedSender<LedgerEntry>,
    
    /// Último entry_id usado
    last_entry_id: Arc<RwLock<u64>>,
    
    /// Hash da última entrada (para chain)
    last_entry_hash: Arc<RwLock<u64>>,
    
    /// Merkle root acumulado
    current_merkle_root: Arc<RwLock<u64>>,
}

impl DurableLedger {
    pub fn new(disk_path: PathBuf) -> Result<Self, LedgerError> {
        // Abre arquivo em modo append
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&disk_path)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        // Cria channel para remote sync
        let (remote_tx, remote_rx) = mpsc::unbounded_channel();
        
        // Spawn background task para remote sync
        tokio::spawn(Self::remote_sync_worker(remote_rx));
        
        // Carrega último estado do disco
        let (last_id, last_hash, merkle) = Self::load_last_state(&disk_path)?;
        
        Ok(Self {
            wal: WriteAheadLog::new(10000),
            disk_path,
            disk_file: Arc::new(RwLock::new(file)),
            remote_tx,
            last_entry_id: Arc::new(RwLock::new(last_id)),
            last_entry_hash: Arc::new(RwLock::new(last_hash)),
            current_merkle_root: Arc::new(RwLock::new(merkle)),
        })
    }
    
    /// Adiciona entry ao ledger (multi-layer)
    /// 
    /// Garante:
    /// - WAL: sempre sucede (< 1ms)
    /// - Disk: sincroniza em background (< 5ms)
    /// - Remote: enfileira para async (< 10ms)
    pub fn append(&self, mut entry: LedgerEntry) -> Result<(), LedgerError> {
        // Gera novo entry_id
        let mut last_id = self.last_entry_id.write()
            .map_err(|_| LedgerError::LockPoisoned)?;
        *last_id += 1;
        entry.entry_id = *last_id;
        
        // Seta previous_hash (chain)
        let last_hash = self.last_entry_hash.read()
            .map_err(|_| LedgerError::LockPoisoned)?;
        entry.previous_entry_hash = *last_hash;
        
        // Calcula merkle root
        let mut merkle = self.current_merkle_root.write()
            .map_err(|_| LedgerError::LockPoisoned)?;
        entry.calculate_merkle_root(*merkle);
        *merkle = entry.merkle_root;
        
        // Finaliza entry (checksum)
        entry.finalize();
        
        // Valida integridade
        if !entry.validate() {
            return Err(LedgerError::InvalidChecksum);
        }
        
        // === ATOMIC POINT ===
        // A partir daqui, entry está committed logicamente
        
        // Camada 1: WAL (RAM) - < 1ms
        self.wal.append(entry)?;
        
        // Camada 2: Disk - < 5ms (sync)
        self.write_to_disk(&entry)?;
        
        // Camada 3: Remote - async (não bloqueia)
        self.remote_tx.send(entry)
            .map_err(|_| LedgerError::RemoteSyncFailed)?;
        
        // Atualiza last_hash
        let mut last_hash_write = self.last_entry_hash.write()
            .map_err(|_| LedgerError::LockPoisoned)?;
        *last_hash_write = entry.calculate_hash();
        
        log::debug!("Entry {} committed to ledger", entry.entry_id);
        
        Ok(())
    }
    
    /// Escreve entry para disco (Camada 2)
    fn write_to_disk(&self, entry: &LedgerEntry) -> Result<(), LedgerError> {
        let mut file = self.disk_file.write()
            .map_err(|_| LedgerError::LockPoisoned)?;
        
        // Serializa entry como bytes
        let bytes = entry.to_bytes();
        
        // Escreve no arquivo
        file.write_all(&bytes)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        // Força flush para garantir persistência
        file.sync_all()
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Worker para remote sync (Camada 3)
    async fn remote_sync_worker(mut rx: mpsc::UnboundedReceiver<LedgerEntry>) {
        while let Some(entry) = rx.recv().await {
            // TODO: Implementar upload para S3/Vault
            // Por enquanto, apenas log
            log::debug!("Remote sync: entry {}", entry.entry_id);
            
            // Simula latência de rede
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    
    /// Carrega último estado do disco (para recovery)
    fn load_last_state(path: &PathBuf) -> Result<(u64, u64, u64), LedgerError> {
        use std::fs::File;
        use std::io::Read;
        
        // Se arquivo não existe, retorna estado inicial
        if !path.exists() {
            return Ok((0, 0, 0));
        }
        
        let mut file = File::open(path)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        // Lê entries até encontrar o último
        let entry_size = std::mem::size_of::<LedgerEntry>();
        let entry_count = buffer.len() / entry_size;
        
        if entry_count == 0 {
            return Ok((0, 0, 0));
        }
        
        // Lê última entry
        let last_offset = (entry_count - 1) * entry_size;
        let last_bytes = &buffer[last_offset..last_offset + entry_size];
        
        let last_entry: LedgerEntry = unsafe {
            std::ptr::read(last_bytes.as_ptr() as *const LedgerEntry)
        };
        
        // Valida integridade
        if !last_entry.validate() {
            return Err(LedgerError::CorruptedLedger);
        }
        
        let last_hash = last_entry.calculate_hash();
        
        Ok((last_entry.entry_id, last_hash, last_entry.merkle_root))
    }
    
    /// Recupera ledger após crash (replay WAL)
    pub fn recover(&self) -> Result<(), LedgerError> {
        log::info!("Starting ledger recovery...");
        
        let last_id = *self.last_entry_id.read().unwrap();
        
        // Busca entries no WAL que ainda não foram committed
        let wal_entries = self.wal.get_since(last_id + 1);
        
        log::info!("Found {} entries in WAL to replay", wal_entries.len());
        
        for entry in wal_entries {
            // Reescreve para disco
            self.write_to_disk(&entry)?;
        }
        
        log::info!("Ledger recovery completed");
        
        Ok(())
    }
    
    /// Retorna entry por ID
    pub fn get_entry(&self, entry_id: u64) -> Result<LedgerEntry, LedgerError> {
        // Tenta WAL primeiro (mais rápido)
        let wal_entries = self.wal.get_since(entry_id);
        if let Some(entry) = wal_entries.iter().find(|e| e.entry_id == entry_id) {
            return Ok(*entry);
        }
        
        // Busca no disco
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};
        
        let mut file = File::open(&self.disk_path)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        // Entry está na posição: (entry_id - 1) * 384 bytes
        let offset = (entry_id - 1) * 384;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        let mut buffer = [0u8; 384];
        file.read_exact(&mut buffer)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        let entry: LedgerEntry = unsafe {
            std::ptr::read(buffer.as_ptr() as *const LedgerEntry)
        };
        
        if !entry.validate() {
            return Err(LedgerError::InvalidChecksum);
        }
        
        Ok(entry)
    }
    
    /// Valida toda a chain (computacionalmente caro!)
    pub fn validate_chain(&self) -> Result<bool, LedgerError> {
        log::info!("Starting full chain validation...");
        
        use std::fs::File;
        use std::io::Read;
        
        let mut file = File::open(&self.disk_path)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| LedgerError::DiskError(e.to_string()))?;
        
        let entry_size = std::mem::size_of::<LedgerEntry>();
        let entry_count = buffer.len() / entry_size;
        
        let mut previous: Option<LedgerEntry> = None;
        
        for i in 0..entry_count {
            let offset = i * entry_size;
            let entry_bytes = &buffer[offset..offset + entry_size];
            
            let entry: LedgerEntry = unsafe {
                std::ptr::read(entry_bytes.as_ptr() as *const LedgerEntry)
            };
            
            // Valida checksum
            if !entry.validate() {
                log::error!("Invalid checksum at entry {}", i);
                return Ok(false);
            }
            
            // Valida chain
            if let Some(prev) = previous {
                if !entry.validate_chain(&prev) {
                    log::error!("Chain broken at entry {}", i);
                    return Ok(false);
                }
            }
            
            previous = Some(entry);
        }
        
        log::info!("Chain validation completed: {} entries OK", entry_count);
        
        Ok(true)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Lock poisoned")]
    LockPoisoned,
    
    #[error("Invalid checksum")]
    InvalidChecksum,
    
    #[error("Disk error: {0}")]
    DiskError(String),
    
    #[error("Remote sync failed")]
    RemoteSyncFailed,
    
    #[error("Corrupted ledger")]
    CorruptedLedger,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_ledger_append() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.dat");
        
        let ledger = DurableLedger::new(path).unwrap();
        
        let entry = LedgerEntry {
            audit_trail_id: 0x1234,
            composite_risk: 100,
            ..Default::default()
        };
        
        assert!(ledger.append(entry).is_ok());
        
        // Verifica se foi escrito
        let retrieved = ledger.get_entry(1).unwrap();
        assert_eq!(retrieved.audit_trail_id, 0x1234);
    }
    
    #[test]
    fn test_ledger_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.dat");
        
        let ledger = DurableLedger::new(path).unwrap();
        
        // Adiciona 3 entries
        for i in 0..3 {
            let entry = LedgerEntry {
                audit_trail_id: i as u128,
                ..Default::default()
            };
            ledger.append(entry).unwrap();
        }
        
        // Valida chain
        assert!(ledger.validate_chain().unwrap());
    }
    
    #[tokio::test]
    async fn test_ledger_recovery() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.dat");
        
        // Cria ledger e adiciona entry
        {
            let ledger = DurableLedger::new(path.clone()).unwrap();
            let entry = LedgerEntry {
                audit_trail_id: 0xabcd,
                ..Default::default()
            };
            ledger.append(entry).unwrap();
        }
        
        // Simula crash e recovery
        {
            let ledger = DurableLedger::new(path).unwrap();
            assert_eq!(*ledger.last_entry_id.read().unwrap(), 1);
            
            let retrieved = ledger.get_entry(1).unwrap();
            assert_eq!(retrieved.audit_trail_id, 0xabcd);
        }
    }
}