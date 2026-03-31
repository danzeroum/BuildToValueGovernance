//! Integration test: Tripartite Ratification — all three branches must sign.
//!
//! Paper 6, Definition 3.3: "Valid(ΔL*) ⇔ σ_L ∧ σ_J ∧ σ_Erep"

use btv_governance::{
    mandate::{AmendmentId, RatificationProof},
    ratification::verify_tripartite_signatures,
};
use chrono::Utc;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

// ── helpers ──────────────────────────────────────────────────────────────────

struct Keys {
    leg:  SigningKey,
    jud:  SigningKey,
    exec: SigningKey,
}

fn make_keys() -> Keys {
    Keys {
        leg:  SigningKey::generate(&mut OsRng),
        jud:  SigningKey::generate(&mut OsRng),
        exec: SigningKey::generate(&mut OsRng),
    }
}

fn make_proof(keys: &Keys, amendment: AmendmentId) -> RatificationProof {
    let nonce:    [u8; 32] = rand::random();
    let ts = Utc::now();

    // Build canonical message
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

    let leg_sig  = keys.leg.sign(&msg).to_bytes();
    let jud_sig  = keys.jud.sign(&msg).to_bytes();
    let exec_sig = keys.exec.sign(&msg).to_bytes();

    RatificationProof {
        amendment,
        legislative_sig:      leg_sig,
        judicial_sig:         jud_sig,
        executive_rep_sig:    exec_sig,
        nonce,
        timestamp: ts,
        legislative_pubkey:   keys.leg.verifying_key().to_bytes(),
        judicial_pubkey:      keys.jud.verifying_key().to_bytes(),
        executive_rep_pubkey: keys.exec.verifying_key().to_bytes(),
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[test]
fn valid_tripartite_ratification_passes() {
    let keys  = make_keys();
    let proof = make_proof(&keys, AmendmentId::Amendment(1));
    assert!(verify_tripartite_signatures(&proof));
}

#[test]
fn missing_legislative_signature_fails() {
    let keys = make_keys();
    let mut proof = make_proof(&keys, AmendmentId::Amendment(1));
    proof.legislative_sig = [0xFF; 64];
    assert!(!verify_tripartite_signatures(&proof));
}

#[test]
fn missing_judicial_signature_fails() {
    let keys = make_keys();
    let mut proof = make_proof(&keys, AmendmentId::Amendment(1));
    proof.judicial_sig = [0xFF; 64];
    assert!(!verify_tripartite_signatures(&proof));
}

#[test]
fn missing_executive_signature_fails() {
    let keys = make_keys();
    let mut proof = make_proof(&keys, AmendmentId::Amendment(1));
    proof.executive_rep_sig = [0xFF; 64];
    assert!(!verify_tripartite_signatures(&proof));
}

/// Paper 6, Theorem 3.4: no two-branch coalition can produce a valid mandate.
#[test]
fn two_branch_coalition_l_j_fails() {
    let keys = make_keys();
    let mut proof = make_proof(&keys, AmendmentId::Amendment(1));
    // Remove Executive — L+J coalition only
    proof.executive_rep_sig = [0u8; 64];
    assert!(!verify_tripartite_signatures(&proof));
}

#[test]
fn two_branch_coalition_l_e_fails() {
    let keys = make_keys();
    let mut proof = make_proof(&keys, AmendmentId::Amendment(1));
    // Remove Judicial — L+E coalition only
    proof.judicial_sig = [0u8; 64];
    assert!(!verify_tripartite_signatures(&proof));
}

#[test]
fn two_branch_coalition_j_e_fails() {
    let keys = make_keys();
    let mut proof = make_proof(&keys, AmendmentId::Amendment(1));
    // Remove Legislative — J+E coalition only
    proof.legislative_sig = [0u8; 64];
    assert!(!verify_tripartite_signatures(&proof));
}

/// Replay attack: reusing a proof for a different amendment fails because
/// the canonical message includes the amendment_id.
#[test]
fn replay_attack_different_amendment_fails() {
    let keys = make_keys();
    // Proof for Amendment(1)
    let proof_1 = make_proof(&keys, AmendmentId::Amendment(1));
    // Re-sign for Amendment(2)
    let proof_2 = make_proof(&keys, AmendmentId::Amendment(2));
    // Craft an attack: take proof_1's sigs, claim it's for Amendment(2)
    let mut attack = proof_2.clone();
    attack.legislative_sig    = proof_1.legislative_sig;
    attack.judicial_sig       = proof_1.judicial_sig;
    attack.executive_rep_sig  = proof_1.executive_rep_sig;
    // Signatures won't verify because message differs
    assert!(!verify_tripartite_signatures(&attack));
}

#[test]
fn genesis_ratification_passes() {
    let keys  = make_keys();
    let proof = make_proof(&keys, AmendmentId::Genesis);
    assert!(verify_tripartite_signatures(&proof));
}
