//! MandateToken<L_v, t_exp> — linear resource binding a legislative version
//! to an expiry timestamp.
//!
//! Paper 6, Definition 3.5:
//! "A MandateToken<L_v, t_exp> is a linear resource binding legislative
//!  version L_v to expiry time t_exp."
//!
//! Invariants:
//! - No `Clone`, no `Copy`  — consumed at most once (linear resource)
//! - `#[must_use]` — silent drop is a compile warning
//! - `mandate_hash` field is private — only `btv-governance` can compute it
//! - `borrow_live()` enforces expiry check at every use

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::GovernanceError;
use crate::ratification::verify_tripartite_signatures;

// ── AmendmentId ──────────────────────────────────────────────────────────────

/// Identifier for a constitutional amendment.
#[derive(
    Debug, Clone, Hash, Eq, PartialEq,
    Serialize, Deserialize,
)]
pub enum AmendmentId {
    /// Genesis mandate (no prior legislative version).
    Genesis,
    /// Numbered amendment — monotonically increasing.
    Amendment(u64),
}

// ── RatificationProof ────────────────────────────────────────────────────────

/// Proof that all three constitutional branches signed a mandate.
///
/// Paper 6, Definition 3.3: "Valid(ΔL*) ⇔ σ_L ∧ σ_J ∧ σ_Erep"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatificationProof {
    /// The amendment that was ratified.
    pub amendment: AmendmentId,

    /// Ed25519 signature — Legislative branch.
    pub legislative_sig: [u8; 64],

    /// Ed25519 signature — Judicial branch.
    pub judicial_sig: [u8; 64],

    /// Ed25519 signature — Executive Representative.
    pub executive_rep_sig: [u8; 64],

    /// Anti-replay nonce — unique per ratification event.
    pub nonce: [u8; 32],

    /// UTC timestamp of ratification.
    pub timestamp: DateTime<Utc>,

    /// Ed25519 verifying keys (32-byte compressed) for each branch.
    pub legislative_pubkey:    [u8; 32],
    pub judicial_pubkey:       [u8; 32],
    pub executive_rep_pubkey:  [u8; 32],
}

// ── MandateToken ─────────────────────────────────────────────────────────────

/// A constitutional mandate — binds a legislative version to an expiry time.
///
/// This is the **only** token that authorises `Verdict::new`.
/// It flows through the Transparency Log (Σ) — never via direct import
/// from `btv-governance` into `btv-executive` (T3 enforced structurally).
///
/// Properties enforced by the type system:
/// - Cannot be cloned or copied (linear resource)
/// - `#[must_use]` — silent drop produces a compile warning
/// - Expiry is checked on every use via `borrow_live()`
#[must_use = "MandateToken must be published in Σ and consumed by the Executive pipeline"]
pub struct MandateToken {
    /// Legislative version this mandate covers.
    pub legislative_version: u64,

    /// UTC expiry — after this instant `is_live()` returns `false`.
    pub expiry: DateTime<Utc>,

    /// Proof of Tripartite Ratification (or genesis proof for v0).
    pub ratification: RatificationProof,

    /// BLAKE3 hash of this mandate (private — only `btv-governance` writes it).
    mandate_hash: [u8; 32],
}

impl MandateToken {
    /// Construct a new mandate from a ratified proof.
    ///
    /// The mandate is **not** yet published in Σ — call
    /// `GovernanceBridge::publish_mandate` after construction.
    pub fn new(
        legislative_version: u64,
        expiry: DateTime<Utc>,
        ratification: RatificationProof,
    ) -> Self {
        let mandate_hash =
            Self::compute_hash(legislative_version, &expiry, &ratification);
        Self {
            legislative_version,
            expiry,
            ratification,
            mandate_hash,
        }
    }

    /// Returns `true` if the mandate has not yet expired.
    ///
    /// Paper 6, Theorem 3.6: if `t_now >= t_exp` the system must enter
    /// Constitutional Interregnum — no new decisions are produced.
    #[inline]
    pub fn is_live(&self) -> bool {
        Utc::now() < self.expiry
    }

    /// Wall-clock time remaining before expiry.
    pub fn time_remaining(&self) -> std::time::Duration {
        let now = Utc::now();
        if now >= self.expiry {
            return std::time::Duration::ZERO;
        }
        (self.expiry - now)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO)
    }

    /// Borrow this mandate only if it is currently live.
    ///
    /// Returns `Err(GovernanceError::MandateExpired)` if expired.
    /// This is the method called by the Executive pipeline when it reads
    /// the mandate from Σ and needs to construct a `Verdict`.
    pub fn borrow_live(&self) -> Result<&Self, GovernanceError> {
        if self.is_live() {
            Ok(self)
        } else {
            Err(GovernanceError::MandateExpired {
                version:    self.legislative_version,
                expired_at: self.expiry,
            })
        }
    }

    /// BLAKE3 hash of this mandate — used as the Σ entry key.
    #[inline]
    pub fn hash(&self) -> &[u8; 32] {
        &self.mandate_hash
    }

    /// Legislative version bound to this mandate.
    #[inline]
    pub fn version(&self) -> u64 {
        self.legislative_version
    }

    /// UTC expiry timestamp.
    #[inline]
    pub fn expiry(&self) -> DateTime<Utc> {
        self.expiry
    }

    /// Verify the embedded Tripartite Ratification proof.
    pub fn verify_ratification(&self) -> bool {
        verify_tripartite_signatures(&self.ratification)
    }

    /// Serialise to wire format for Σ publication and Executive consumption.
    pub fn to_wire(&self) -> MandateWire {
        MandateWire {
            legislative_version: self.legislative_version,
            expiry_utc:          self.expiry.timestamp(),
            ratification:        self.ratification.clone(),
            mandate_hash:        self.mandate_hash,
        }
    }

    // ── private ──────────────────────────────────────────────────────────────

    fn compute_hash(
        version:     u64,
        expiry:      &DateTime<Utc>,
        ratification: &RatificationProof,
    ) -> [u8; 32] {
        let mut data = Vec::with_capacity(8 + 8 + 64 + 64 + 64 + 32);
        data.extend_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&expiry.timestamp().to_le_bytes());
        data.extend_from_slice(&ratification.legislative_sig);
        data.extend_from_slice(&ratification.judicial_sig);
        data.extend_from_slice(&ratification.executive_rep_sig);
        data.extend_from_slice(&ratification.nonce);
        blake3::hash(&data).into()
    }
}

// NO Clone, NO Copy — MandateToken is a linear resource

// ── MandateWire ──────────────────────────────────────────────────────────────

/// Wire representation of a MandateToken.
///
/// This is what flows through Σ and is consumed by `btv-executive`.
/// It contains no private state and can be freely cloned / serialised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateWire {
    /// Legislative version bound to this mandate.
    pub legislative_version: u64,

    /// UTC expiry as Unix timestamp (seconds).
    pub expiry_utc: i64,

    /// Tripartite ratification proof.
    pub ratification: RatificationProof,

    /// BLAKE3 hash — used to verify wire integrity.
    pub mandate_hash: [u8; 32],
}

impl MandateWire {
    /// Returns `true` if the mandate has not yet expired.
    #[inline]
    pub fn is_live(&self) -> bool {
        Utc::now().timestamp() < self.expiry_utc
    }
}
