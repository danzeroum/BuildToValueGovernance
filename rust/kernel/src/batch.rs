//! BatchProcessor v1.0.0 — F1.5-03
//! Processa múltiplos inputs com timeout per-item.
//! Sem Protobuf nesta versão (bincode interno, JSON/Proto na FFI).

use crate::gatekeeper::Gatekeeper;
use crate::evidence::TechnicalEvidence;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------
// BATCH RESULT
// ---------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchItemStatus {
    Ok,
    Timeout,
    Error(String),
}

#[derive(Debug)]
pub struct BatchItem {
    pub index: usize,
    pub audit_trail_id: u128,
    pub evidence: Option<TechnicalEvidence>,
    pub status: BatchItemStatus,
    pub processing_time_us: u64,
}

#[derive(Debug)]
pub struct BatchResult {
    pub items: Vec<BatchItem>,
    pub total_time_us: u64,
    pub succeeded: usize,
    pub timed_out: usize,
    pub failed: usize,
}

// ---------------------------------------------------------------------
// BATCH CONFIG
// ---------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Max inputs per batch
    pub max_batch_size: usize,
    /// Timeout per individual item (microseconds)
    pub item_timeout_us: u64,
    /// Timeout for entire batch (microseconds)
    pub batch_timeout_us: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            item_timeout_us: 10_000,      // 10ms per item
            batch_timeout_us: 1_000_000,  // 1s total
        }
    }
}

// ---------------------------------------------------------------------
// BATCH PROCESSOR
// ---------------------------------------------------------------------
pub struct BatchProcessor {
    config: BatchConfig,
}

impl BatchProcessor {
    pub fn new(config: BatchConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(BatchConfig::default())
    }

    /// Process a batch of inputs through the gatekeeper.
    /// Fail-secure: timeout or error → item marked, never skipped silently.
    pub fn process(
        &self,
        gatekeeper: &mut Gatekeeper,
        inputs: &[&str],
        audit_trail_ids: &[u128],
    ) -> Result<BatchResult, BatchError> {
        // Validation
        if inputs.len() != audit_trail_ids.len() {
            return Err(BatchError::LengthMismatch {
                inputs: inputs.len(),
                ids: audit_trail_ids.len(),
            });
        }
        if inputs.is_empty() {
            return Err(BatchError::EmptyBatch);
        }
        if inputs.len() > self.config.max_batch_size {
            return Err(BatchError::ExceedsMaxSize {
                size: inputs.len(),
                max: self.config.max_batch_size,
            });
        }

        let batch_start = Instant::now();
        let batch_deadline = batch_start + Duration::from_micros(self.config.batch_timeout_us);
        let item_timeout = Duration::from_micros(self.config.item_timeout_us);

        let mut items = Vec::with_capacity(inputs.len());
        let mut succeeded = 0usize;
        let mut timed_out = 0usize;
        let failed = 0usize;

        for (i, (input, &trail_id)) in inputs.iter().zip(audit_trail_ids.iter()).enumerate() {
            // Check batch-level deadline
            if Instant::now() >= batch_deadline {
                // Mark remaining as timed out (fail-secure)
                for j in i..inputs.len() {
                    items.push(BatchItem {
                        index: j,
                        audit_trail_id: audit_trail_ids[j],
                        evidence: None,
                        status: BatchItemStatus::Timeout,
                        processing_time_us: 0,
                    });
                    timed_out += 1;
                }
                break;
            }

            let item_start = Instant::now();
            let evidence = gatekeeper.scan_for_evidence(input, trail_id);
            let elapsed = item_start.elapsed();

            if elapsed > item_timeout {
                // Item completed but exceeded per-item timeout — still return evidence
                // but flag as timeout for observability (Levinas: don't discard work)
                items.push(BatchItem {
                    index: i,
                    audit_trail_id: trail_id,
                    evidence: Some(evidence),
                    status: BatchItemStatus::Timeout,
                    processing_time_us: elapsed.as_micros() as u64,
                });
                timed_out += 1;
            } else {
                items.push(BatchItem {
                    index: i,
                    audit_trail_id: trail_id,
                    evidence: Some(evidence),
                    status: BatchItemStatus::Ok,
                    processing_time_us: elapsed.as_micros() as u64,
                });
                succeeded += 1;
            }
        }

        let total_time_us = batch_start.elapsed().as_micros() as u64;

        Ok(BatchResult {
            items,
            total_time_us,
            succeeded,
            timed_out,
            failed,
        })
    }

    pub fn config(&self) -> &BatchConfig {
        &self.config
    }
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------
// ERRORS
// ---------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    EmptyBatch,
    LengthMismatch { inputs: usize, ids: usize },
    ExceedsMaxSize { size: usize, max: usize },
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "Empty batch"),
            Self::LengthMismatch { inputs, ids } => {
                write!(f, "Length mismatch: {} inputs, {} ids", inputs, ids)
            }
            Self::ExceedsMaxSize { size, max } => {
                write!(f, "Batch size {} exceeds max {}", size, max)
            }
        }
    }
}

impl std::error::Error for BatchError {}