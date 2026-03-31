//! Bridge between `btv-kernel`'s `TechnicalEvidence` and `btv-core`'s linear types.
//!
//! The kernel produces raw findings and statistics.
//! This module converts them into the deterministic `evidence_bytes` that
//! `EvidenceToken::new` will hash, and into structured `FindingRecord`s
//! that `DecisionMaker` uses.
//!
//! **This is the only module that imports both `btv-kernel` and `btv-core`.**
//! All other modules import only one or the other.

use btv_types::RiskLevel;

/// Structured scan output — bridges kernel scan to constitutional types.
pub struct ScanResult {
    pub findings:         Vec<FindingRecord>,
    pub composite_risk:   f32,
    pub risk_level:       RiskLevel,
    pub statistics:       InputStatistics,
    /// Deterministically serialised bytes fed to `EvidenceToken::new`.
    pub evidence_bytes:   Vec<u8>,
    pub executed_stages:  u8,
    pub detected_language: String,
    pub scan_duration_us: u64,
}

#[derive(Debug, Clone)]
pub struct FindingRecord {
    pub rule_id:          String,
    pub title:            String,
    pub severity:         u8,  // 0-255
    pub confidence:       u8,  // 0-255
    pub validator_module: String,
    pub category:         String,
}

#[derive(Debug, Clone, Copy)]
pub struct InputStatistics {
    pub entropy:      f32,
    pub z_score:      f32,
    pub input_size:   usize,
    pub digit_ratio:  f32,
    pub letter_ratio: f32,
    pub symbol_ratio: f32,
    pub unique_chars: usize,
    pub total_chars:  usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Input size violation: {0} bytes (max 64 KiB)")]
    InputSizeViolation(usize),
    #[error("Input is not valid UTF-8")]
    InvalidUtf8,
    #[error("Kernel scan error: {0}")]
    KernelError(String),
}

/// Thin wrapper around `btv_kernel::Gatekeeper`.
///
/// Does NOT replicate scan logic — delegates entirely to the kernel.
/// Only responsibility: convert `TechnicalEvidence` → `ScanResult`.
pub struct GatekeeperBridge;

impl GatekeeperBridge {
    pub fn new() -> Self { Self }

    /// Execute the kernel's 3-stage pipeline and convert output to `ScanResult`.
    pub fn scan(&self, input: &[u8]) -> Result<ScanResult, ScanError> {
        if input.is_empty() || input.len() > 64 * 1024 {
            return Err(ScanError::InputSizeViolation(input.len()));
        }
        let input_str = std::str::from_utf8(input)
            .map_err(|_| ScanError::InvalidUtf8)?;

        let start = std::time::Instant::now();

        // Delegate to kernel gatekeeper
        let kernel_result = btv_kernel::Gatekeeper::default()
            .scan(input_str)
            .map_err(|e| ScanError::KernelError(e.to_string()))?;

        let findings: Vec<FindingRecord> = kernel_result
            .findings
            .iter()
            .map(|f| FindingRecord {
                rule_id:          f.rule_id.clone(),
                title:            f.title.clone(),
                severity:         severity_to_u8(f.severity),
                confidence:       (f.confidence * 255.0) as u8,
                validator_module: f.module.clone(),
                category:         f.category.clone(),
            })
            .collect();

        let statistics = InputStatistics {
            entropy:      kernel_result.entropy,
            z_score:      kernel_result.z_score,
            input_size:   input.len(),
            digit_ratio:  kernel_result.digit_ratio,
            letter_ratio: kernel_result.letter_ratio,
            symbol_ratio: kernel_result.symbol_ratio,
            unique_chars: kernel_result.unique_chars,
            total_chars:  kernel_result.total_chars,
        };

        let composite_risk = compute_composite_risk(&findings);
        let risk_level     = RiskLevel::from_score(composite_risk);

        let original_hash: [u8; 32] = blake3::hash(input).into();
        let evidence_bytes = build_evidence_bytes(&original_hash, &findings, &statistics);

        Ok(ScanResult {
            findings,
            composite_risk,
            risk_level,
            statistics,
            evidence_bytes,
            executed_stages: kernel_result.executed_stages,
            detected_language: kernel_result.detected_language,
            scan_duration_us: start.elapsed().as_micros() as u64,
        })
    }
}

// ── Private helpers ─────────────────────────────────────────────────────────

fn severity_to_u8(s: btv_kernel::TechnicalSeverity) -> u8 {
    match s {
        btv_kernel::TechnicalSeverity::Critical => 230,
        btv_kernel::TechnicalSeverity::High     => 180,
        btv_kernel::TechnicalSeverity::Medium   => 120,
        btv_kernel::TechnicalSeverity::Low      => 60,
        btv_kernel::TechnicalSeverity::Info     => 20,
    }
}

fn compute_composite_risk(findings: &[FindingRecord]) -> f32 {
    if findings.is_empty() { return 0.0; }
    let sum: f32 = findings.iter()
        .map(|f| (f.severity as f32 / 255.0) * (f.confidence as f32 / 255.0))
        .sum();
    (sum / findings.len() as f32).min(1.0)
}

/// Deterministic serialisation of scan evidence for `EvidenceToken`.
/// Same input → same bytes → same BLAKE3 hash → reproducible audit trail.
fn build_evidence_bytes(
    original_hash: &[u8; 32],
    findings: &[FindingRecord],
    stats: &InputStatistics,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256 + findings.len() * 128);

    // 1. Placeholder for total length prefix (filled at end)
    buf.extend_from_slice(&[0u8; 8]);

    // 2. Original input BLAKE3 hash
    buf.extend_from_slice(original_hash);

    // 3. Statistics (deterministic LE encoding)
    buf.extend_from_slice(&stats.entropy.to_le_bytes());
    buf.extend_from_slice(&stats.z_score.to_le_bytes());
    buf.extend_from_slice(&(stats.input_size as u64).to_le_bytes());
    buf.extend_from_slice(&stats.digit_ratio.to_le_bytes());
    buf.extend_from_slice(&stats.letter_ratio.to_le_bytes());
    buf.extend_from_slice(&stats.symbol_ratio.to_le_bytes());
    buf.extend_from_slice(&(stats.unique_chars as u64).to_le_bytes());
    buf.extend_from_slice(&(stats.total_chars as u64).to_le_bytes());

    // 4. Findings sorted: severity DESC, then rule_id ASC (deterministic)
    let mut sorted: Vec<&FindingRecord> = findings.iter().collect();
    sorted.sort_unstable_by(|a, b| {
        b.severity.cmp(&a.severity)
            .then_with(|| a.rule_id.as_str().cmp(b.rule_id.as_str()))
    });
    for f in sorted {
        buf.extend_from_slice(f.rule_id.as_bytes());
        buf.push(0x00); // null separator
        buf.push(f.severity);
        buf.push(f.confidence);
        buf.extend_from_slice(f.validator_module.as_bytes());
        buf.push(0x00);
    }

    // 5. Write total length into placeholder
    let total = (buf.len() - 8) as u64;
    buf[..8].copy_from_slice(&total.to_le_bytes());

    buf
}
