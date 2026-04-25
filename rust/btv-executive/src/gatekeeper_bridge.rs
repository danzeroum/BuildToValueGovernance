//! Bridge between `btv-kernel`'s `TechnicalEvidence` and `btv-core`'s linear types.
//!
//! The kernel produces raw findings and statistics.
//! This module converts them into the deterministic `evidence_bytes` that
//! `EvidenceToken::new` will hash, and into structured `FindingRecord`s
//! that `DecisionMaker` uses.
//!
//! **This is the only module that imports both `btv-kernel` and `btv-core`.**
//! All other modules import only one or the other.

use buildtovalue_kernel::TechnicalSeverity;
use btv_types::RiskLevel;

/// Structured scan output — bridges kernel scan to constitutional types.
#[derive(Debug)]
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
}

/// Thin wrapper around `buildtovalue_kernel::Gatekeeper`.
///
/// Does NOT replicate scan logic — delegates entirely to the kernel.
/// Only responsibility: convert `TechnicalEvidence` → `ScanResult`.
pub struct GatekeeperBridge;

impl Default for GatekeeperBridge {
    fn default() -> Self { Self::new() }
}

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

        // Delegate to kernel gatekeeper — returns TechnicalEvidence directly (no Result)
        let audit_id = 0u128;
        let ev = buildtovalue_kernel::Gatekeeper::new()
            .scan_for_evidence(input_str, audit_id);

        // Convert all findings (normal + critical) to Vec<FindingRecord>
        let findings: Vec<FindingRecord> = ev.get_all_findings()
            .into_iter()
            .map(|f| {
                let rule_id = fixed_to_string(&f.rule_id);
                let category = fixed_to_string(&f.threat_category);
                let module_name = format!("{:?}", f.module);
                FindingRecord {
                    rule_id:          rule_id.clone(),
                    title:            rule_id,
                    severity:         severity_to_u8(f.severity),
                    confidence:       f.confidence,
                    validator_module: module_name,
                    category,
                }
            })
            .collect();

        let stats = ev.stats;
        let statistics = InputStatistics {
            entropy:      stats.entropy,
            z_score:      stats.z_score,
            input_size:   stats.input_size as usize,
            digit_ratio:  stats.digit_ratio,
            letter_ratio: stats.letter_ratio,
            symbol_ratio: stats.symbol_ratio,
            unique_chars: stats.unique_chars as usize,
            total_chars:  stats.total_chars as usize,
        };

        let composite_risk = ev.composite_risk;
        let risk_level = RiskLevel::from_score(composite_risk);

        let original_hash: [u8; 32] = blake3::hash(input).into();
        let evidence_bytes = build_evidence_bytes(&original_hash, &findings, &statistics);

        // executed_modules is u32 bitmask; count set bits for a comparable u8 stage count
        let executed_stages = ev.executed_modules.count_ones() as u8;

        Ok(ScanResult {
            findings,
            composite_risk,
            risk_level,
            statistics,
            evidence_bytes,
            executed_stages,
            detected_language: String::new(),
            scan_duration_us: start.elapsed().as_micros() as u64,
        })
    }
}

// ── Private helpers ─────────────────────────────────────────────────────────

/// Encode a float as a stable i64 (4 decimal places) to avoid ULP non-determinism
/// from HashMap-based accumulators in the kernel's statistics computation.
fn stable_float(v: f32) -> [u8; 8] {
    ((v * 10_000.0).round() as i64).to_le_bytes()
}

fn fixed_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

fn severity_to_u8(s: TechnicalSeverity) -> u8 {
    match s {
        TechnicalSeverity::Critical(_)      => 230,
        TechnicalSeverity::PolicyViolation  => 230,
        TechnicalSeverity::High             => 180,
        TechnicalSeverity::Medium           => 120,
        TechnicalSeverity::Low              => 60,
        TechnicalSeverity::Info             => 20,
    }
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

    // 3. Statistics (stable integer encoding — floats rounded to 4dp to avoid ULP noise)
    buf.extend_from_slice(&stable_float(stats.entropy));
    buf.extend_from_slice(&stable_float(stats.z_score));
    buf.extend_from_slice(&(stats.input_size as u64).to_le_bytes());
    buf.extend_from_slice(&stable_float(stats.digit_ratio));
    buf.extend_from_slice(&stable_float(stats.letter_ratio));
    buf.extend_from_slice(&stable_float(stats.symbol_ratio));
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
