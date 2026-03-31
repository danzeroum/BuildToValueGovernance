//! `Executive` — único ponto de entrada para decisões.
//!
//! Paper 5, Theorem 3.5 (Executive Containment):
//! "the execution path Decide → Deliver is type-constrained;
//!  no well-typed program can produce a DeliveryPayload without
//!  traversing EvidenceToken ⊗ ComplianceToken → Verdict → InclusionReceipt."
use btv_core::{
    EvidenceToken, ComplianceAuthority, Verdict,
    DeliveryToken, LogClient,
};
use btv_types::{Decision, RiskLevel, DeliveryPayload};
use crate::gatekeeper_bridge::GatekeeperBridge;
use crate::decision::DecisionMaker;
use crate::error::DecisionError;

/// Summary of the gatekeeper scan — for observability/logging only.
/// Does NOT influence decision logic (that's `DecisionMaker`'s job).
#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub findings_count:   usize,
    pub critical_count:   usize,
    pub risk_level:       RiskLevel,
    pub composite_risk:   f32,
    pub executed_stages:  u8,
    pub input_entropy:    f32,
    pub detected_language: String,
    pub scan_duration_us: u64,
}

impl From<&crate::gatekeeper_bridge::ScanResult> for ScanSummary {
    fn from(r: &crate::gatekeeper_bridge::ScanResult) -> Self {
        Self {
            findings_count:    r.findings.len(),
            critical_count:    r.findings.iter().filter(|f| f.severity >= 200).count(),
            risk_level:        r.risk_level,
            composite_risk:    r.composite_risk,
            executed_stages:   r.executed_stages,
            input_entropy:     r.statistics.entropy,
            detected_language: r.detected_language.clone(),
            scan_duration_us:  r.scan_duration_us,
        }
    }
}

/// Full output of a successful `Executive::decide()` call.
pub struct ExecutiveResult {
    pub delivery:            DeliveryPayload,
    pub scan_summary:        ScanSummary,
    pub decision_latency_us: u64,
}

/// The Executive power — sole authority to produce a `DeliveryPayload`.
///
/// Constitutional constraints (all enforced by the type system):
/// 1. Cannot produce delivery without `EvidenceToken` (Phase 1, Axiom 4.3)
/// 2. Cannot produce delivery without `ComplianceToken` (Phase 1, Axiom 4.4)
/// 3. Cannot produce delivery without `InclusionReceipt` (Phase 2, Eq. 1)
/// 4. Cannot modify policies (Legislative prerogative — not exposed here)
/// 5. Cannot audit (Judicial prerogative — not exposed here)
pub struct Executive {
    authority:       ComplianceAuthority,
    log_client:      LogClient,
    scanner:         GatekeeperBridge,
    decision_maker:  DecisionMaker,
}

impl Executive {
    pub fn new(
        authority:      ComplianceAuthority,
        log_client:     LogClient,
        decision_maker: DecisionMaker,
    ) -> Self {
        Self {
            authority,
            log_client,
            scanner: GatekeeperBridge::new(),
            decision_maker,
        }
    }

    /// Construct from environment variables (deployment convenience).
    /// Requires `BTV_LOG_VERIFYING_KEY` and optional `BTV_LOG_ENDPOINT`.
    pub fn from_env(authority: ComplianceAuthority) -> Result<Self, DecisionError> {
        let log_client = LogClient::from_env()
            .map_err(|e| DecisionError::LogUnavailable(e.to_string()))?;
        Ok(Self::new(authority, log_client, DecisionMaker::default_thresholds()))
    }

    /// The SOLE method to produce a decision.
    ///
    /// Returns `Ok(ExecutiveResult)` only when all 7 steps succeed.
    /// Any failure returns `Err(DecisionError)` — no partial result is accessible.
    pub async fn decide(
        &self,
        context:        &[u8],
        jurisdiction:   &str,
        policy_version: &str,
    ) -> Result<ExecutiveResult, DecisionError> {
        let start = std::time::Instant::now();

        // ── Step 1: Scan ──────────────────────────────────────────────────────
        let scan = self.scanner.scan(context)
            .map_err(|e| DecisionError::GatekeeperFailed(e.to_string()))?;

        let summary = ScanSummary::from(&scan);

        // ── Step 2: Decide ────────────────────────────────────────────────────
        let decision    = self.decision_maker.decide(&scan);
        let explanation = self.decision_maker.explain(&scan, &decision);

        // ── Step 3: EvidenceToken (linear, consumed by Verdict::new) ─────────
        let evidence = EvidenceToken::new(&scan.evidence_bytes);

        // ── Step 4: ComplianceToken (linear, consumed by Verdict::new) ───────
        let compliance = self.authority
            .issue(jurisdiction, policy_version)
            .map_err(|e| DecisionError::ComplianceUnavailable(e.to_string()))?;

        // ── Step 5: Verdict (consumes E ⊗ C — both tokens are moved) ─────────
        let verdict = Verdict::new(evidence, compliance, decision, explanation);

        // ── Step 6: Submit to Σ (btv-sigma via HTTP) ─────────────────────────
        let verdict_hash: [u8; 32] = verdict.to_record().evidence_hash.0;
        let receipt = self.log_client
            .submit_and_await(&verdict_hash)
            .await
            .map_err(|e| DecisionError::LogUnavailable(e.to_string()))?;

        // ── Step 7: Seal + Deliver (consumes V ⊗ R) ──────────────────────────
        let token = DeliveryToken::seal(&verdict, receipt)
            .map_err(|_| DecisionError::IntegrityFailure)?;
        let delivery = token.deliver();

        Ok(ExecutiveResult {
            delivery,
            scan_summary: summary,
            decision_latency_us: start.elapsed().as_micros() as u64,
        })
    }
}
