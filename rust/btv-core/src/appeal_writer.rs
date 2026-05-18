//! `AppealWriter` — async off-chain persistence for contestation records (ADR-062).
//!
//! Architecture:
//! - Non-blocking enqueue via `tokio::sync::mpsc` channel (zero latency on hot path).
//! - Background worker consumes the channel and persists to `appeals.db` (SQLite).
//! - Authenticity is verified at display time via BLAKE3 hash comparison, not here.
//!
//! Feature-gated behind `appeal-writer` to keep the hot path free of SQLite/async deps.
#![cfg(feature = "appeal-writer")]

use tokio::sync::mpsc;
use btv_types::AppealRecord;

const CHANNEL_CAPACITY: usize = 1024;

/// Error returned when the channel is full (backpressure).
#[derive(Debug, thiserror::Error)]
pub enum AppealWriteError {
    #[error("appeal writer channel is full — backpressure")]
    ChannelFull,
}

/// Non-blocking writer that enqueues AppealRecords for async SQLite persistence.
///
/// Construct with `AppealWriter::new()` and hold the returned `JoinHandle` for the
/// background worker. Drop the handle to let the worker finish its queue and stop.
pub struct AppealWriter {
    tx: mpsc::Sender<AppealRecord>,
}

impl AppealWriter {
    /// Spawns the background SQLite writer and returns the writer + task handle.
    ///
    /// The worker opens (or creates) `db_path` immediately. Panics on startup if the
    /// file cannot be opened — intentional fail-fast during server initialization.
    pub fn new(db_path: &str) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<AppealRecord>(CHANNEL_CAPACITY);
        let db_path = db_path.to_string();

        let handle = tokio::spawn(async move {
            let conn = rusqlite::Connection::open(&db_path)
                .expect("appeals.db must be openable at startup");
            init_schema(&conn);

            while let Some(record) = rx.recv().await {
                if let Err(e) = persist_record(&conn, &record) {
                    // Log but do NOT panic — system continues without appeal persistence.
                    // Observability alert should fire; investigation is offline.
                    tracing::error!("AppealWriter: failed to persist record for evidence_hash={}: {}", hex::encode(record.evidence_hash), e);
                }
            }
        });

        (Self { tx }, handle)
    }

    /// Enqueue a record for async persistence. Non-blocking.
    ///
    /// Returns `Err(ChannelFull)` only if the channel is at capacity (1024 records).
    /// In that case, log and continue — contestation records are best-effort pre-v1.1.
    pub fn enqueue(&self, record: AppealRecord) -> Result<(), AppealWriteError> {
        self.tx.try_send(record).map_err(|_| AppealWriteError::ChannelFull)
    }
}

fn init_schema(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS appeal_records (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_hash         BLOB    NOT NULL UNIQUE,
            explanation_text      TEXT    NOT NULL,
            bias_declaration_json TEXT    NOT NULL,
            deadlock_reason_json  TEXT,
            appeal_token          TEXT    NOT NULL UNIQUE,
            appeal_sla_deadline   INTEGER NOT NULL,
            created_at            INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_appeal_token
            ON appeal_records(appeal_token);

        CREATE INDEX IF NOT EXISTS idx_evidence_hash
            ON appeal_records(evidence_hash);

        INSERT OR IGNORE INTO schema_version VALUES (1, strftime('%s', 'now'));
        ",
    )
    .expect("appeal schema initialization must succeed at startup");
}

fn persist_record(
    conn: &rusqlite::Connection,
    record: &AppealRecord,
) -> rusqlite::Result<()> {
    let bias_json = serde_json::to_string(&record.bias_declaration)
        .unwrap_or_else(|_| "{}".to_string());
    let deadlock_json = record.deadlock_reason.as_ref()
        .and_then(|d| serde_json::to_string(d).ok());

    conn.execute(
        "INSERT OR IGNORE INTO appeal_records
         (evidence_hash, explanation_text, bias_declaration_json,
          deadlock_reason_json, appeal_token, appeal_sla_deadline, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            record.evidence_hash.as_slice(),
            record.explanation_text,
            bias_json,
            deadlock_json,
            record.appeal_token,
            record.appeal_sla_deadline as i64,
            record.created_at as i64,
        ],
    )?;
    Ok(())
}
