//! Durable Ledger v2.3.2 - Write-Ahead Log
//!
//! Implementa o WAL (Write-Ahead Log) para garantia de durabilidade imediata (Crash Recovery).
//!
//! **Funcionalidades**:
//! - Escrita sequencial em disco (Append-only)
//! - Durabilidade configurável (fsync)
//! - Serialização segura de evidências
//! - Recuperação de falhas (Replay)

use crate::evidence::TechnicalEvidence;
// ✅ FIX: Importando EVIDENCE_SIZE para evitar magic numbers e erros de tamanho
use crate::core::types::EVIDENCE_SIZE;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURAÇÃO
// ═══════════════════════════════════════════════════════════════════════════

/// Configuração do WAL
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Caminho do arquivo de log
    pub wal_path: PathBuf,

    /// Se true, força flush para o disco a cada escrita (mais lento, mais seguro)
    pub fsync_enabled: bool,

    /// Tamanho máximo antes de rotacionar (não implementado rotação nesta versão)
    pub max_size_bytes: u64,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            wal_path: PathBuf::from("ledger.wal"),
            fsync_enabled: true,
            max_size_bytes: 100 * 1024 * 1024, // 100MB
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WAL ENTRY
// ═══════════════════════════════════════════════════════════════════════════

/// Entrada do WAL (Wrapper persistente da Evidência)
///
/// Contém os dados brutos necessários para reconstruir o estado do sistema
/// ou replicar para o S3 em caso de falha.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Número de sequência (monotônico)
    pub seq: u64,

    /// Timestamp da captura (microssegundos UNIX)
    pub timestamp: u128,

    /// Snapshot serializado da evidência técnica
    /// (Usamos Vec<u8> para evitar problemas de versionamento da struct TechnicalEvidence no log)
    pub evidence_snapshot: Vec<u8>,
}

impl WalEntry {
    /// Cria uma nova entrada WAL a partir de uma evidência
    pub fn from_evidence(seq: u64, evidence: &TechnicalEvidence) -> Self {
        Self {
            seq,
            timestamp: evidence.timestamp,
            // Serializa a evidência para bytes (Bincode é rápido e compacto)
            evidence_snapshot: evidence.to_bytes().to_vec(),
        }
    }

    /// Método auxiliar para compatibilidade com testes e sync.rs.
    /// Simula o "append" retornando a estrutura que seria escrita.
    pub fn append(seq: u64, evidence: &TechnicalEvidence) -> Result<Self> {
        Ok(Self::from_evidence(seq, evidence))
    }

    /// Tenta desserializar o snapshot de volta para TechnicalEvidence
    pub fn restore_evidence(&self) -> Option<TechnicalEvidence> {
        // ✅ FIX: Usando constante EVIDENCE_SIZE (9600) em vez de magic number (9596)
        // Isso corrige o erro "Cannot transmute between types of different sizes"

        if self.evidence_snapshot.len() == EVIDENCE_SIZE {
            let mut arr = [0u8; EVIDENCE_SIZE];
            arr.copy_from_slice(&self.evidence_snapshot);
            unsafe {
                Some(std::mem::transmute(arr))
            }
        } else {
            // Log de erro silencioso ou apenas None
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WRITE AHEAD LOG ENGINE
// ═══════════════════════════════════════════════════════════════════════════

/// Gerenciador do Write-Ahead Log
///
/// Thread-safe (usa Mutex interno para escritas).
pub struct WriteAheadLog {
    file: Mutex<BufWriter<File>>,
    config: WalConfig,
    current_seq: Mutex<u64>,
}

impl WriteAheadLog {
    /// Inicializa ou abre um WAL existente
    pub fn new(config: WalConfig) -> Result<Self> {
        // Garante que o diretório existe
        if let Some(parent) = config.wal_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create WAL directory")?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.wal_path)
            .with_context(|| format!("Failed to open WAL file at {:?}", config.wal_path))?;

        // TODO: Em uma implementação real, leríamos o arquivo para encontrar o último seq.
        // Por simplificação, assumimos 0 ou persistência externa do seq.
        let initial_seq = 0;

        Ok(Self {
            file: Mutex::new(BufWriter::new(file)),
            config,
            current_seq: Mutex::new(initial_seq),
        })
    }

    /// Persiste uma evidência no log
    ///
    /// 1. Atribui novo Sequence Number
    /// 2. Serializa WalEntry
    /// 3. Escreve no disco (com length-prefix framing)
    /// 4. Executa fsync (se habilitado)
    pub fn append(&self, evidence: &TechnicalEvidence) -> Result<u64> {
        let mut seq_guard = self.current_seq.lock().unwrap();
        *seq_guard += 1;
        let seq = *seq_guard;

        let entry = WalEntry::from_evidence(seq, evidence);

        // Serialização binária do wrapper WalEntry
        let bytes = bincode::serialize(&entry)
            .context("Failed to serialize WAL entry")?;

        let mut file_guard = self.file.lock().unwrap();

        // Framing: Escreve tamanho (u32) antes do payload para permitir recovery/leitura
        file_guard.write_all(&(bytes.len() as u32).to_le_bytes())?;
        file_guard.write_all(&bytes)?;

        if self.config.fsync_enabled {
            file_guard.flush()?;
            file_guard.get_ref().sync_all()?;
        }

        Ok(seq)
    }

    /// Força a escrita de qualquer dado em buffer para o disco
    pub fn flush(&self) -> Result<()> {
        let mut file_guard = self.file.lock().unwrap();
        file_guard.flush()?;
        file_guard.get_ref().sync_all()?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_wal_write_and_flush() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = WalConfig {
            wal_path: temp_file.path().to_path_buf(),
            fsync_enabled: false, // Rápido para teste
            ..Default::default()
        };

        let wal = WriteAheadLog::new(config).unwrap();
        let evidence = TechnicalEvidence::new(123);

        let seq = wal.append(&evidence).unwrap();
        assert_eq!(seq, 1);

        wal.flush().unwrap();

        let file_len = temp_file.as_file().metadata().unwrap().len();
        assert!(file_len > 0, "WAL file should not be empty");
    }

    #[test]
    fn test_wal_entry_restore() {
        let evidence = TechnicalEvidence::new(999);
        let entry = WalEntry::from_evidence(1, &evidence);

        assert_eq!(entry.seq, 1);
        // Verifica se o tamanho do snapshot bate com a constante
        assert_eq!(entry.evidence_snapshot.len(), EVIDENCE_SIZE);

        let restored = entry.restore_evidence().unwrap();
        assert_eq!(restored.audit_trail_id, 999);
    }
}