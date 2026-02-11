//! Durable Ledger v2.3.2
//!
//! Orquestrador de persistência híbrida (Disk + Remote).
//! Garante que toda evidência gerada seja persistida em disco (WAL) antes
//! de ser processada ou enviada para a nuvem (S3).
//!
//! **Garantias**:
//! - Durabilidade Local: Imediata (fsync)
//! - Durabilidade Remota: Eventual (Async via Channel)
//! - Fail-safe: Se S3 falhar, dados estão salvos no WAL local.

use std::path::PathBuf;
use std::sync::mpsc;
use anyhow::{Result, Context};

use crate::ledger::wal::{WriteAheadLog, WalConfig, WalEntry};
use crate::ledger::remote::sync::{RemoteConfig, RemoteSyncService};
use crate::evidence::TechnicalEvidence;

/// Erros específicos do Ledger
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization Error: {0}")]
    Serialization(String),
    #[error("Remote Sync Error: {0}")]
    Remote(String),
    #[error("Initialization Error: {0}")]
    Init(String),
}

/// O Ledger Durável
///
/// Mantém o WAL aberto e um canal de comunicação com o serviço de sync em background.
pub struct DurableLedger {
    /// Log de escrita antecipada (Disk)
    wal: WriteAheadLog,

    /// Canal para enviar entradas para o serviço de sync (S3)
    sync_sender: mpsc::Sender<WalEntry>,
}

impl DurableLedger {
    /// Inicializa o Ledger Durável (versão síncrona)
    ///
    /// # Argumentos
    /// * `wal_config` - Configuração do WAL (caminho e opções).
    /// * `remote_config` - Configuração para o upload remoto (S3/Mock).
    ///
    /// # Retorno
    /// Retorna a instância do Ledger. O serviço de sync é iniciado em background.
    pub fn new(wal_config: WalConfig, remote_config: RemoteConfig) -> Result<Self> {
        // 1. Inicializa WAL (Disk)
        let wal = WriteAheadLog::new(wal_config)
            .context("Failed to initialize Write-Ahead Log")?;

        // 2. Cria canal para comunicação com serviço de sync
        let (tx, rx) = mpsc::channel::<WalEntry>();

        // 3. Inicializa e executa serviço de sync em thread separada
        let sync_service = RemoteSyncService::new(remote_config, rx);
        std::thread::spawn(move || {
            sync_service.run();
        });

        log::info!("DurableLedger initialized at {:?}", wal.config.wal_path);

        Ok(Self {
            wal,
            sync_sender: tx,
        })
    }

    /// Persiste uma evidência técnica.
    ///
    /// # Fluxo
    /// 1. **Serialização & WAL**: Escreve no disco imediatamente (síncrono/fsync).
    /// 2. **Memória**: Cria o objeto `WalEntry`.
    /// 3. **Remote Sync**: Envia para o canal de upload (assíncrono).
    ///
    /// Retorna o número de sequência (seq) da entrada.
    pub fn append(&self, evidence: &TechnicalEvidence) -> Result<u64> {
        // 1. WAL (Critical Path - Blocking I/O for safety)
        // Garante que se a energia cair agora, o dado está no disco.
        let seq = self.wal.append(evidence)
            .context("Failed to append to WAL")?;

        // 2. Prepara entrada para sync
        let entry = WalEntry::from_evidence(seq, evidence);

        // 3. Dispatch to Remote Sync (Best Effort / Non-blocking)
        // Se falhar, o dado JÁ ESTÁ NO WAL.
        match self.sync_sender.send(entry) {
            Ok(_) => {},
            Err(e) => {
                log::warn!("Remote sync channel error. Entry {} persisted to disk but sync failed: {}", seq, e);
            }
        }

        Ok(seq)
    }

    /// Força flush do WAL para o disco.
    pub fn flush(&self) -> Result<()> {
        self.wal.flush().context("Failed to flush WAL")
    }

    /// Retorna métricas básicas do ledger
    pub fn get_metrics(&self) -> LedgerMetrics {
        LedgerMetrics::default()
    }
}

/// Métricas básicas do ledger
#[derive(Debug, Default)]
pub struct LedgerMetrics {
    pub entries_total: u64,
    pub bytes_written: u64,
    pub fsync_count: u64,
    pub fsync_failures: u64,
    pub avg_append_ms: f64,
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_durable_ledger_lifecycle() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let wal_config = WalConfig {
            wal_path: wal_path.clone(),
            fsync_enabled: false, // Para testes rápidos
            ..Default::default()
        };

        let remote_config = RemoteConfig {
            enabled: false, // Desativa sync remoto para teste
            ..Default::default()
        };

        let ledger = DurableLedger::new(wal_config, remote_config)
            .expect("Failed to create ledger");

        // Cria evidência dummy
        let evidence = TechnicalEvidence::new(12345); // ID de teste

        // Append
        let seq = ledger.append(&evidence).expect("Append failed");
        assert_eq!(seq, 1); // Primeira entrada deve ser seq 1 (se WAL novo)

        // Append de novo
        let seq2 = ledger.append(&evidence).expect("Append 2 failed");
        assert_eq!(seq2, 2);

        // Verifica se arquivo existe
        assert!(wal_path.exists());

        // Flush
        ledger.flush().unwrap();
    }
}