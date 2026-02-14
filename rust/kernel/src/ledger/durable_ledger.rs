//! Durable Ledger v2.3.2 – versão simplificada (sem sync remoto)

use std::path::PathBuf;
use std::sync::mpsc;
use anyhow::{Result, Context};

use crate::ledger::wal::{WriteAheadLog, WalConfig, WalEntry};
use crate::evidence::TechnicalEvidence;

/// O Ledger Durável (apenas WAL local por enquanto)
pub struct DurableLedger {
    wal: WriteAheadLog,
    // Placeholder para futura sincronização
    _sync_sender: mpsc::Sender<WalEntry>,
}

impl DurableLedger {
    /// Inicializa o Ledger com WAL local.
    /// (sync remoto será adicionado posteriormente)
    pub fn new(wal_config: WalConfig) -> Result<Self> {
        let wal = WriteAheadLog::new(wal_config)
            .context("Failed to initialize Write-Ahead Log")?;

        // Canal dummy (não utilizado por enquanto)
        let (tx, _rx) = mpsc::channel::<WalEntry>();

        log::info!("DurableLedger initialized at {:?}", wal.config.wal_path);

        Ok(Self {
            wal,
            _sync_sender: tx,
        })
    }

    /// Persiste uma evidência técnica no WAL.
    pub fn append(&self, evidence: &TechnicalEvidence) -> Result<u64> {
        let seq = self.wal.append(evidence)
            .context("Failed to append to WAL")?;

        // Futuramente: enviar para sync remoto via self.sync_sender

        Ok(seq)
    }

    /// Força flush do WAL.
    pub fn flush(&self) -> Result<()> {
        self.wal.flush().context("Failed to flush WAL")
    }

    /// Métricas básicas (placeholder)
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