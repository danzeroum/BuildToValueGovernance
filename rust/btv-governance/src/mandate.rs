//! MandateToken<L_v, t_exp> — linear resource binding a legislative version
//! to an expiry timestamp.
//!
//! Paper 6, Definition 3.5:
//! "A MandateToken<L_v, t_exp> is a linear resource binding legislative
//!  version L_v to expiry time t_exp."
//!
//! Invariants:
//! - No `Clone`, no `Copy`  — consumed at most once (linear resource)
//! - `#[must_use]`          — silent drop is a compile warning
//! - `mandate_hash` field is private — only `btv-governance` can compute it
//! - `borrow_live()` enforces expiry check at every use
//!
//! # Serde note
//! `serde` does not derive `Deserialize` for `[u8; N]` when N > 32.
//! We provide `serde_hex` helpers (hex string wire format) using the
//! `hex` crate already present in the workspace.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::GovernanceError;
use crate::ratification::verify_tripartite_signatures;

// ── serde helpers for fixed-size byte arrays ─────────────────────────────────

mod serde_hex {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error};

    pub mod bytes_64 {
        use super::*;

        pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&hex::encode(v))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
            let s = String::deserialize(d)?;
            let b = hex::decode(&s).map_err(D::Error::custom)?;
            b.try_into().map_err(|_| D::Error::custom("expected 64-byte hex string"))
        }
    }

    pub mod bytes_32 {
        use super::*;

        pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&hex::encode(v))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let s = String::deserialize(d)?;
            let b = hex::decode(&s).map_err(D::Error::custom)?;
            b.try_into().map_err(|_| D::Error::custom("expected 32-byte hex string"))
        }
    }
}

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
///
/// All `[u8; 64]` (signatures) and `[u8; 32]` (keys / nonce) fields
/// are serialised as lowercase hex strings for JSON/YAML compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatificationProof {
    pub amendment: AmendmentId,

    #[serde(with = "serde_hex::bytes_64")]
    pub legislative_sig: [u8; 64],

    #[serde(with = "serde_hex::bytes_64")]
    pub judicial_sig: [u8; 64],

    #[serde(with = "serde_hex::bytes_64")]
    pub executive_rep_sig: [u8; 64],

    #[serde(with = "serde_hex::bytes_32")]
    pub nonce: [u8; 32],

    pub timestamp: DateTime<Utc>,

    #[serde(with = "serde_hex::bytes_32")]
    pub legislative_pubkey: [u8; 32],

    #[serde(with = "serde_hex::bytes_32")]
    pub judicial_pubkey: [u8; 32],

    #[serde(with = "serde_hex::bytes_32")]
    pub executive_rep_pubkey: [u8; 32],
}

// ── MandateToken ─────────────────────────────────────────────────────────────

/// A constitutional mandate — binds a legislative version to an expiry time.
///
/// The **only** token that authorises `Verdict::new`.
/// Flows through Σ (Transparency Log) — never via direct Rust import into
/// `btv-executive` (T3 structurally enforced).
///
/// - No `Clone`, no `Copy` — linear resource
/// - `#[must_use]` — silent drop is a compile warning
/// - Expiry checked on every use via `borrow_live()`
#[must_use = "MandateToken must be published in Σ and consumed by the Executive pipeline"]
pub struct MandateToken {
    pub legislative_version: u64,
    pub expiry: DateTime<Utc>,
    pub ratification: RatificationProof,
    mandate_hash: [u8; 32],
}

impl MandateToken {
    pub fn new(
        legislative_version: u64,
        expiry: DateTime<Utc>,
        ratification: RatificationProof,
    ) -> Self {
        let mandate_hash = Self::compute_hash(legislative_version, &expiry, &ratification);
        Self { legislative_version, expiry, ratification, mandate_hash }
    }

    #[inline]
    pub fn is_live(&self) -> bool {
        Utc::now() < self.expiry
    }

    pub fn time_remaining(&self) -> std::time::Duration {
        let now = Utc::now();
        if now >= self.expiry {
            return std::time::Duration::ZERO;
        }
        (self.expiry - now).to_std().unwrap_or(std::time::Duration::ZERO)
    }

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

    #[inline]
    pub fn hash(&self) -> &[u8; 32] { &self.mandate_hash }

    #[inline]
    pub fn version(&self) -> u64 { self.legislative_version }

    #[inline]
    pub fn expiry(&self) -> DateTime<Utc> { self.expiry }

    pub fn verify_ratification(&self) -> bool {
        verify_tripartite_signatures(&self.ratification)
    }

    pub fn to_wire(&self) -> MandateWire {
        MandateWire {
            legislative_version: self.legislative_version,
            expiry_utc:          self.expiry.timestamp(),
            ratification:        self.ratification.clone(),
            mandate_hash:        self.mandate_hash,
        }
    }

    fn compute_hash(
        version:      u64,
        expiry:       &DateTime<Utc>,
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

/// Serialisable wire format of a MandateToken.
/// Flows through Σ; consumed by `btv-executive` via JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateWire {
    pub legislative_version: u64,
    pub expiry_utc: i64,
    pub ratification: RatificationProof,
    #[serde(with = "serde_hex::bytes_32")]
    pub mandate_hash: [u8; 32],
}

impl MandateWire {
    #[inline]
    pub fn is_live(&self) -> bool {
        Utc::now().timestamp() < self.expiry_utc
    }
}
