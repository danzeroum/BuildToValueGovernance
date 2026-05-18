//! `Verdict` — the sole product of consuming `EvidenceToken ⊗ ComplianceToken`.
//!
//! Paper 1, Definition 4.1:
//! "Verdict::new is the sole constructor of the type Verdict; no other term of
//!  that type is well-typed in Safe Rust."
//!
//! All fields are private → struct-literal construction is E0451.
//! Both `evidence` and `compliance` are taken by value → the type-system enforces
//! the ⊗-introduction rule (Axiom 4.3): both resources are consumed simultaneously.

use crate::evidence_token::EvidenceToken;
use crate::compliance_token::ComplianceToken;
use crate::hash::Blake3Hash;
use crate::hmac::{compute_seal, constant_time_eq};
use btv_types::{Decision, VerdictRecord, BiasDeclaration, NegotiationDeadlockReason, AppealRecord};

/// A materialized verdict — the product of consuming `E ⊗ C`.
///
/// All fields are private. The only way to produce a `Verdict` is via `Verdict::new`,
/// which simultaneously consumes one `EvidenceToken` and one `ComplianceToken`.
pub struct Verdict {
    evidence_hash: Blake3Hash,  // private
    decision: Decision,         // private
    explanation: String,        // private
    hmac_seal: [u8; 32],        // private
    jurisdiction: String,       // private
    policy_version: String,     // private
}

impl Verdict {
    /// The sole constructor. Implements Axiom 4.3 (⊗-I).
    ///
    /// Both `evidence` and `compliance` are taken **by value** (moved).
    /// After this call, neither token is accessible to the caller — the
    /// Rust borrow checker enforces this at compile time.
    ///
    /// The HMAC seal binds `evidence_hash || decision || explanation` into a
    /// tamper-evident record using the key from `BTV_HMAC_KEY`.
    pub fn new(
        evidence: EvidenceToken,
        compliance: ComplianceToken,
        decision: Decision,
        explanation: String,
    ) -> Self {
        let hash = evidence.consume();   // pub(crate) — only callable here
        let seal = compute_seal(hash.as_bytes(), &decision, explanation.as_bytes());

        Self {
            jurisdiction: compliance.jurisdiction().to_string(),
            policy_version: compliance.policy_version().to_string(),
            evidence_hash: hash,
            decision,
            explanation,
            hmac_seal: seal,
        }
    }

    /// Export to wire format for persistence in Σ and judicial verification.
    ///
    /// `legislative_version: 0` is a placeholder — will carry the `MandateToken`
    /// version in Phase 6.
    ///
    /// `bias_declaration` uses `bootstrap_unvalidated()` until real measurements are
    /// provided. The bootstrap string in `validated_groups` triggers Dashboard alerts.
    pub fn to_record(&self) -> VerdictRecord {
        VerdictRecord {
            evidence_hash: self.evidence_hash.to_wire(),
            decision: self.decision,
            explanation_hash: btv_types::Blake3Hash(
                *blake3::hash(self.explanation.as_bytes()).as_bytes()
            ),
            hmac_tag: self.hmac_seal,
            legislative_version: 0,
            bias_declaration: BiasDeclaration::bootstrap_unvalidated(),
        }
    }

    /// Export to wire format AND produce an off-chain AppealRecord for contestation.
    ///
    /// The caller must enqueue the AppealRecord via AppealWriter — it must NOT be
    /// returned directly to the end-user (only the `appeal_token` is client-visible).
    ///
    /// `appeal_key`: 32-byte server secret for keyed BLAKE3 token derivation.
    /// `now_unix`: current Unix timestamp in seconds.
    /// `deadlock_reason`: Some only when the Block originated from negotiation deadlock.
    pub fn to_record_with_appeal(
        &self,
        appeal_key: &[u8; 32],
        now_unix: u64,
        deadlock_reason: Option<NegotiationDeadlockReason>,
    ) -> (VerdictRecord, AppealRecord) {
        let verdict_record = self.to_record();
        let evidence_bytes = self.evidence_hash.as_bytes();
        let appeal_token = hex::encode(
            blake3::keyed_hash(appeal_key, evidence_bytes).as_bytes()
        );

        let appeal_record = AppealRecord {
            evidence_hash: *evidence_bytes,
            explanation_text: self.explanation.clone(),
            bias_declaration: verdict_record.bias_declaration.clone(),
            deadlock_reason,
            appeal_token,
            appeal_sla_deadline: now_unix + 86400,
            created_at: now_unix,
        };

        (verdict_record, appeal_record)
    }

    /// Verify the integrity of this verdict's HMAC seal.
    ///
    /// Returns `true` iff the seal matches the current key and content.
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_integrity(&self) -> bool {
        let expected = compute_seal(
            self.evidence_hash.as_bytes(),
            &self.decision,
            self.explanation.as_bytes(),
        );
        constant_time_eq(&self.hmac_seal, &expected)
    }

    pub fn decision(&self) -> Decision {
        self.decision
    }

    pub fn jurisdiction(&self) -> &str {
        &self.jurisdiction
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
}
