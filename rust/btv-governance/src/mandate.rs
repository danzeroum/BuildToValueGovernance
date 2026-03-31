//! MandateToken<L_v, t_exp> — linear resource binding a legislative version
//! to an expiry timestamp.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::GovernanceError;
use crate::ratification::verify_tripartite_signatures;

// ── serde helpers ──────────────────────────────────────────────────────────────

mod serde_hex {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error};

    pub mod bytes_64 {
        use super::*;
        pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&hex::encode(v))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
            let s = String::deserialize(d)?;
            hex::decode(&s)
                .map_err(D::Error::custom)?
                .try_into()
                .map_err(|_| D::Error::custom("expected 64-byte hex string"))
        }
    }

    pub mod bytes_32 {
        use super::*;
        pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&hex::encode(v))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let s = String::deserialize(d)?;
            hex::decode(&s)
                .map_err(D::Error::custom)?
                .try_into()
                .map_err(|_| D::Error::custom("expected 32-byte hex string"))
        }
    }
}

// ── AmendmentId ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum AmendmentId {
    Genesis,
    Amendment(u64),
}

// ── RatificationProof ────────────────────────────────────────────────────────

/// Paper 6, Def 3.3: "Valid(ΔL*) ⇔ σ_L ∧ σ_J ∧ σ_Erep"
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for RatificationProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatificationProof")
            .field("amendment",           &self.amendment)
            .field("legislative_sig",     &hex::encode(self.legislative_sig))
            .field("judicial_sig",        &hex::encode(self.judicial_sig))
            .field("executive_rep_sig",   &hex::encode(self.executive_rep_sig))
            .field("nonce",               &hex::encode(self.nonce))
            .field("timestamp",           &self.timestamp)
            .field("legislative_pubkey",  &hex::encode(self.legislative_pubkey))
            .field("judicial_pubkey",     &hex::encode(self.judicial_pubkey))
            .field("executive_rep_pubkey",&hex::encode(self.executive_rep_pubkey))
            .finish()
    }
}

// ── MandateToken ─────────────────────────────────────────────────────────────

/// Paper 6, Def 3.5 — linear resource, no Clone/Copy.
/// `mandate_hash` is private; Debug shows it as hex.
#[must_use = "MandateToken must be published in Σ and consumed by the Executive pipeline"]
pub struct MandateToken {
    pub legislative_version: u64,
    pub expiry: DateTime<Utc>,
    pub ratification: RatificationProof,
    mandate_hash: [u8; 32],
}

impl std::fmt::Debug for MandateToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MandateToken")
            .field("legislative_version", &self.legislative_version)
            .field("expiry",              &self.expiry)
            .field("mandate_hash",        &hex::encode(self.mandate_hash))
            .field("ratification",        &self.ratification)
            .finish()
    }
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

    #[inline] pub fn is_live(&self) -> bool { Utc::now() < self.expiry }

    pub fn time_remaining(&self) -> std::time::Duration {
        let now = Utc::now();
        if now >= self.expiry { return std::time::Duration::ZERO; }
        (self.expiry - now).to_std().unwrap_or(std::time::Duration::ZERO)
    }

    pub fn borrow_live(&self) -> Result<&Self, GovernanceError> {
        if self.is_live() { Ok(self) }
        else {
            Err(GovernanceError::MandateExpired {
                version:    self.legislative_version,
                expired_at: self.expiry,
            })
        }
    }

    #[inline] pub fn hash(&self)    -> &[u8; 32]     { &self.mandate_hash }
    #[inline] pub fn version(&self) -> u64           { self.legislative_version }
    #[inline] pub fn expiry(&self)  -> DateTime<Utc> { self.expiry }

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
    pub fn is_live(&self) -> bool { Utc::now().timestamp() < self.expiry_utc }
}
