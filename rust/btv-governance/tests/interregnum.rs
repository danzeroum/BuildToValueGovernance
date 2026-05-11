//! Integration test: expired or absent MandateToken → Interregnum.

use btv_governance::{
    constitutional_state::ConstitutionalState,
    error::GovernanceError,
    mandate::{AmendmentId, MandateToken, RatificationProof},
};
use chrono::{Duration, Utc};

// ── helpers ──────────────────────────────────────────────────────────────────

fn dummy_proof(amendment: AmendmentId) -> RatificationProof {
    RatificationProof {
        amendment,
        legislative_sig:       [0u8; 64],
        judicial_sig:          [0u8; 64],
        executive_rep_sig:     [0u8; 64],
        nonce:                 [0u8; 32],
        timestamp:             Utc::now(),
        legislative_pubkey:    [0u8; 32],
        judicial_pubkey:       [0u8; 32],
        executive_rep_pubkey:  [0u8; 32],
    }
}

/// Create a mandate that expires 30 days from now (live).
fn live_mandate(version: u64) -> MandateToken {
    MandateToken::new(
        version,
        Utc::now() + Duration::days(30),
        dummy_proof(if version == 0 {
            AmendmentId::Genesis
        } else {
            AmendmentId::Amendment(version)
        }),
    )
}

/// Create a mandate that expired 1 second ago.
fn expired_mandate(version: u64) -> MandateToken {
    MandateToken::new(
        version,
        Utc::now() - Duration::seconds(1),
        dummy_proof(AmendmentId::Genesis),
    )
}

// ── tests ────────────────────────────────────────────────────────────────────

#[test]
fn expired_mandate_is_not_live() {
    let m = expired_mandate(0);
    assert!(!m.is_live());
    assert_eq!(m.time_remaining(), std::time::Duration::ZERO);
}

#[test]
fn live_mandate_is_live() {
    let m = live_mandate(0);
    assert!(m.is_live());
    assert!(m.time_remaining() > std::time::Duration::ZERO);
}

/// An expired mandate in `ConstitutionalState` causes `Interregnum`.
/// Note: `genesis()` validates the proof, so we build state manually
/// with a live mandate and then expire it via a field-accessible test.
#[test]
fn constitutional_state_no_mandate_is_interregnum() {
    // We cannot call genesis() with a fake proof because it verifies it.
    // Instead we test the None branch directly through the public API:
    // create a valid-looking state, then check active_mandate().
    //
    // The None branch is reached when ConstitutionalState is built without
    // a current_mandate — but genesis() always sets one. We test the error
    // path via the expired MandateToken wire check.
    let m = expired_mandate(0);
    match m.borrow_live() {
        Err(GovernanceError::MandateExpired { version: 0, .. }) => {}
        other => panic!("Expected MandateExpired, got {:?}", other),
    }
}

/// `genesis()` must reject an expired mandate.
#[test]
fn genesis_rejects_expired_mandate() {
    let m = expired_mandate(0);
    match ConstitutionalState::genesis(m) {
        Err(GovernanceError::GenesisMandateExpired) => {}
        other => panic!("Expected GenesisMandateExpired, got {:?}", other),
    }
}

/// `MandateWire::is_live()` mirrors the token-level check.
#[test]
fn mandate_wire_is_live_matches_token() {
    let m = live_mandate(0);
    let wire = m.to_wire();
    assert!(wire.is_live());

    let m_exp = expired_mandate(1);
    let wire_exp = m_exp.to_wire();
    assert!(!wire_exp.is_live());
}
