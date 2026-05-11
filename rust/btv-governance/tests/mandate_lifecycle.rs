//! Integration test: full MandateToken lifecycle — create, wire, version bump.

#![allow(clippy::expect_used, clippy::unwrap_used)] // testes de integração: pânico = asserção

use btv_governance::{
    amendment::{Amendment, AmendmentKind, PolicyDelta},
    constitutional_state::{ConstitutionalState, SystemState},
    error::GovernanceError,
    mandate::{AmendmentId, MandateToken, RatificationProof},
};
use chrono::{Duration, Utc};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_signed_mandate(version: u64, expiry_days: i64) -> MandateToken {
    let leg  = SigningKey::generate(&mut OsRng);
    let jud  = SigningKey::generate(&mut OsRng);
    let exec = SigningKey::generate(&mut OsRng);

    let amendment = if version == 0 {
        AmendmentId::Genesis
    } else {
        AmendmentId::Amendment(version)
    };
    let nonce: [u8; 32] = rand::random();
    let ts = Utc::now();

    let mut msg: Vec<u8> = Vec::new();
    match &amendment {
        AmendmentId::Genesis => msg.extend_from_slice(b"GENESIS\x00"),
        AmendmentId::Amendment(n) => {
            msg.extend_from_slice(b"AMEND:\x00\x00");
            msg.extend_from_slice(&n.to_le_bytes());
        }
    }
    msg.extend_from_slice(&nonce);
    msg.extend_from_slice(&ts.timestamp().to_le_bytes());

    let proof = RatificationProof {
        amendment,
        legislative_sig:      leg.sign(&msg).to_bytes(),
        judicial_sig:         jud.sign(&msg).to_bytes(),
        executive_rep_sig:    exec.sign(&msg).to_bytes(),
        nonce,
        timestamp: ts,
        legislative_pubkey:   leg.verifying_key().to_bytes(),
        judicial_pubkey:      jud.verifying_key().to_bytes(),
        executive_rep_pubkey: exec.verifying_key().to_bytes(),
    };

    MandateToken::new(
        version,
        Utc::now() + Duration::days(expiry_days),
        proof,
    )
}

// ── tests ────────────────────────────────────────────────────────────────────

#[test]
fn genesis_state_is_active() {
    let m = make_signed_mandate(0, 30);
    let state = ConstitutionalState::genesis(m).expect("genesis must succeed");
    match state.state() {
        SystemState::Active { version: 0, .. } => {}
        other => panic!("Expected Active v0, got {:?}", other),
    }
}

#[test]
fn mandate_wire_round_trip() {
    let m    = make_signed_mandate(0, 30);
    let wire = m.to_wire();
    assert_eq!(wire.legislative_version, 0);
    assert!(wire.is_live());
    assert_eq!(&wire.mandate_hash, m.hash());
}

#[test]
fn version_bump_via_apply_amendment() {
    let genesis = make_signed_mandate(0, 30);
    let mut state = ConstitutionalState::genesis(genesis).expect("genesis");

    let amendment = Amendment {
        id:               AmendmentId::Amendment(1),
        kind:             AmendmentKind::PolicyUpdate(PolicyDelta {
            changed_files:      vec!["data/policies/default.yaml".into()],
            change_description: "Initial threshold calibration".into(),
        }),
        description:      "v0 → v1 policy update".into(),
        target_version:   1,
        previous_version: 0,
        proposed_at:      Utc::now(),
        nonce:            rand::random(),
    };
    let new_mandate = make_signed_mandate(1, 30);
    state.apply_amendment(amendment, new_mandate).expect("apply_amendment must succeed");

    assert_eq!(state.current_version, 1);
    match state.state() {
        SystemState::Active { version: 1, .. } => {}
        other => panic!("Expected Active v1, got {:?}", other),
    }
    assert_eq!(state.mandate_count(), 2);
}

#[test]
fn skipping_version_is_rejected() {
    let genesis = make_signed_mandate(0, 30);
    let mut state = ConstitutionalState::genesis(genesis).expect("genesis");

    let amendment = Amendment {
        id:               AmendmentId::Amendment(2), // skips v1
        kind:             AmendmentKind::PolicyUpdate(PolicyDelta {
            changed_files:      vec![],
            change_description: "Skipped".into(),
        }),
        description:      "Version skip attempt".into(),
        target_version:   2,
        previous_version: 0,
        proposed_at:      Utc::now(),
        nonce:            [0u8; 32],
    };
    let bad_mandate = make_signed_mandate(2, 30);
    match state.apply_amendment(amendment, bad_mandate) {
        Err(GovernanceError::VersionMismatch { expected: 1, got: 2 }) => {}
        other => panic!("Expected VersionMismatch(1, 2), got {:?}", other),
    }
}
