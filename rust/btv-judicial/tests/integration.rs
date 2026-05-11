//! Testes de integração do btv-judicial.
//!
//! Testes de rede requerem btv-sigma rodando em localhost:3100.
//! Testes unitários (HMAC, Merkle) rodam sem rede.
#![allow(clippy::unwrap_used)]
use btv_judicial::{HmacVerifier, JudicialAuditor};
// fix(unused-imports): removido alias duplicado de JudicialAuditor.
// btv_judicial::JudicialAuditor já está no escopo via use acima.
use btv_types::{Blake3Hash, Decision, VerdictRecord, MerkleProof};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const TEST_KEY: &[u8] = b"judicial-test-key-32bytes-pad!!";

fn make_verdict_with_valid_hmac() -> VerdictRecord {
    let mut mac = HmacSha256::new_from_slice(TEST_KEY).unwrap();
    mac.update(&[0x01; 32]); // evidence_hash
    mac.update(&[0u8]);       // Decision::Allow = 0
    mac.update(&[0x02; 32]); // explanation_hash
    let tag: [u8; 32] = mac.finalize().into_bytes().into();

    VerdictRecord {
        evidence_hash:       Blake3Hash([0x01; 32]),
        decision:            Decision::Allow,
        explanation_hash:    Blake3Hash([0x02; 32]),
        hmac_tag:            tag,
        legislative_version: 1,
    }
}

#[test]
fn valid_hmac_verified() {
    let verifier = HmacVerifier::new(TEST_KEY.to_vec());
    let verdict = make_verdict_with_valid_hmac();
    assert!(verifier.verify(&verdict).unwrap());
}

#[test]
fn forged_hmac_rejected() {
    let verifier = HmacVerifier::new(TEST_KEY.to_vec());
    let mut verdict = make_verdict_with_valid_hmac();
    verdict.hmac_tag = [0xFF; 32];
    assert!(!verifier.verify(&verdict).unwrap());
}

#[test]
fn merkle_empty_proof_leaf_is_root() {
    let leaf = [0x42u8; 32];
    let proof = MerkleProof { path: vec![], leaf_index: 0 };
    assert!(btv_judicial::verify_merkle_inclusion(&leaf, &leaf, &proof));
}

#[test]
fn audit_report_sign_verify() {
    let auditor = JudicialAuditor::new("ci-auditor".into());
    let mut report = btv_judicial::audit_report::AuditReport {
        report_id:         "r-001".into(),
        timestamp:         "2026-03-30T00:00:00Z".into(),
        payloads_verified: 5,
        payloads_passed:   5,
        payloads_failed:   0,
        failures:          vec![],
        auditor_id:        "ci-auditor".into(),
        log_root:          [0u8; 32],
        tree_size:         5,
        signature:         [0u8; 64],
        auditor_pubkey:    [0u8; 32],
    };
    auditor.sign_report(&mut report);
    assert!(btv_judicial::audit_report::JudicialAuditor::verify_report(&report));
}

#[test]
fn tampered_report_fails() {
    let auditor = JudicialAuditor::new("ci-auditor".into());
    let mut report = btv_judicial::audit_report::AuditReport {
        report_id:         "r-002".into(),
        timestamp:         "2026-03-30T00:00:00Z".into(),
        payloads_verified: 3,
        payloads_passed:   3,
        payloads_failed:   0,
        failures:          vec![],
        auditor_id:        "ci-auditor".into(),
        log_root:          [0u8; 32],
        tree_size:         3,
        signature:         [0u8; 64],
        auditor_pubkey:    [0u8; 32],
    };
    auditor.sign_report(&mut report);
    report.payloads_failed = 99; // tamper
    assert!(!btv_judicial::audit_report::JudicialAuditor::verify_report(&report));
}
