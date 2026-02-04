
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

/// Write-Ahead Log (RAM buffer)
/// 
/// Armazena entries temporariamente antes de flush para disco.
/// Latência: < 1ms
/// Durabilidade: Perdido em crash
pub struct WriteAheadLog {
    /// Buffer circular em memória (capacidade: 10000 entries)
    buffer: Arc<RwLock<VecDeque<LedgerEntry>>>,
    
    /// Capacidade máxima do buffer
    capacity: usize,
    
    /// Número de entries adicionados (stats)
    total_appends: Arc<RwLock<u64>>,
}

impl WriteAheadLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(capacity))),
            capacity,
            total_appends: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Adiciona entry ao WAL (RAM only)
    pub fn append(&self, entry: LedgerEntry) -> Result<(), LedgerError> {
        let mut buffer = self.buffer.write()
            .map_err(|_| LedgerError::LockPoisoned)?;
        
        // Se buffer cheio, remove mais antigo (FIFO)
        if buffer.len() >= self.capacity {
            buffer.pop_front();
            log::warn!("WAL buffer full, dropping oldest entry");
        }
        
        buffer.push_back(entry);
        
        // Incrementa contador
        let mut total = self.total_appends.write()
            .map_err(|_| LedgerError::LockPoisoned)?;
        *total += 1;
        
        Ok(())
    }
    
    /// Retorna entries desde um ID (para replay)
    pub fn get_since(&self, entry_id: u64) -> Vec<LedgerEntry> {
        let buffer = self.buffer.read().unwrap();
        
        buffer.iter()
            .filter(|e| e.entry_id >= entry_id)
            .copied()
            .collect()
    }
    
    /// Retorna todas as entries (para flush)
    pub fn drain_all(&self) -> Vec<LedgerEntry> {
        let mut buffer = self.buffer.write().unwrap();
        buffer.drain(..).collect()
    }
    
    /// Retorna estatísticas
    pub fn stats(&self) -> WalStats {
        let buffer = self.buffer.read().unwrap();
        let total = self.total_appends.read().unwrap();
        
        WalStats {
            current_size: buffer.len(),
            capacity: self.capacity,
            total_appends: *total,
            utilization: buffer.len() as f32 / self.capacity as f32,
        }
    }
}

#[derive(Debug)]
pub struct WalStats {
    pub current_size: usize,
    pub capacity: usize,
    pub total_appends: u64,
    pub utilization: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wal_append() {
        let wal = WriteAheadLog::new(100);
        
        let entry = LedgerEntry {
            entry_id: 1,
            ..Default::default()
        };
        
        assert!(wal.append(entry).is_ok());
        
        let stats = wal.stats();
        assert_eq!(stats.current_size, 1);
        assert_eq!(stats.total_appends, 1);
    }
    
    #[test]
    fn test_wal_overflow() {
        let wal = WriteAheadLog::new(10);
        
        // Adiciona 15 entries (excede capacidade)
        for i in 0..15 {
            let entry = LedgerEntry {
                entry_id: i,
                ..Default::default()
            };
            wal.append(entry).unwrap();
        }
        
        let stats = wal.stats();
        assert_eq!(stats.current_size, 10);  // Limitado pela capacidade
        assert_eq!(stats.total_appends, 15);
    }
}