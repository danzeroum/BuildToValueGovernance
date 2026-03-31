//! Testes de integração do btv-redaction.
//!
//! Executa o protocolo em modo direct (zk_enabled = false) para CI.
//! Os testes ZK reais requerem toolchain Noir (Semanas 18-30).
use btv_redaction::{
    AccountableRedaction, RedactionConfig, RedactionError, RedactionVerifier,
    GroupStats, LedgerStatistics, RedactionEntry,
    state_commitment::StateCommitment,
};
use ed25519_dalek::{SigningKey, Signer};
use rand::RngCore;

fn test_config() -> RedactionConfig {
    RedactionConfig {
        epsilon:           0.05,
        max_batch_size:    100,
        protected_groups:  vec![
            "gender:female".into(), "gender:male".into(),
            "race:black".into(),    "race:white".into(),
        ],
        zk_enabled: false,
    }
}

fn sample_stats() -> LedgerStatistics {
    LedgerStatistics {
        groups: vec![
            GroupStats { group_label: "gender:female".into(), total: 1000, approved: 800,  denied: 200, redacted: 0 },
            GroupStats { group_label: "gender:male".into(),   total: 1000, approved: 820,  denied: 180, redacted: 0 },
            GroupStats { group_label: "race:black".into(),    total: 500,  approved: 400,  denied: 100, redacted: 0 },
            GroupStats { group_label: "race:white".into(),    total: 500,  approved: 420,  denied:  80, redacted: 0 },
        ],
        total_decisions: 3000,
        timestamp: 1_700_000_000,
    }
}

fn make_entry(group: &str, approved: bool, seed: u8) -> RedactionEntry {
    let mut secret = [seed; 32];
    let sk = SigningKey::from_bytes(&secret);
    let verdict_hash = [seed; 32];
    let timestamp: u64 = 1_700_000_001;

    let mut msg = Vec::new();
    msg.extend_from_slice(&verdict_hash);
    msg.extend_from_slice(group.as_bytes());
    msg.push(0);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    msg.extend_from_slice(b"REQUEST_ERASURE");

    let sig = sk.sign(&msg);
    RedactionEntry {
        verdict_hash,
        group_label:       group.into(),
        was_approved:      approved,
        subject_signature: sig.to_bytes(),
        subject_pubkey:    *sk.verifying_key().as_bytes(),
    }
}

#[tokio::test]
async fn balanced_redaction_passes() {
    let engine = AccountableRedaction::new(test_config(), RedactionVerifier::placeholder());
    let stats  = sample_stats();

    let entries = vec![
        make_entry("gender:female", true,  0),
        make_entry("gender:female", false, 1),
        make_entry("gender:male",   true,  2),
        make_entry("gender:male",   false, 3),
        make_entry("race:black",    true,  4),
        make_entry("race:black",    false, 5),
        make_entry("race:white",    true,  6),
        make_entry("race:white",    false, 7),
    ];

    let result = engine.execute(&stats, entries, 1_700_000_001).await;
    assert!(result.is_ok(), "Balanced redaction should pass: {:?}", result.err());
}

#[tokio::test]
async fn selective_deletion_detected() {
    let engine = AccountableRedaction::new(
        RedactionConfig { epsilon: 0.02, ..test_config() },
        RedactionVerifier::placeholder(),
    );
    let stats = sample_stats();

    // Remove 100 denied de gender:female: taxa sobe de 80% para ~89% (delta=0.09 > epsilon=0.02)
    let entries: Vec<RedactionEntry> = (0..100u8)
        .map(|i| make_entry("gender:female", false, i))
        .collect();

    let result = engine.execute(&stats, entries, 1_700_000_002).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        RedactionError::EpsilonViolation { group, delta, epsilon } => {
            assert!(group.contains("female"), "Expected female group, got {group}");
            assert!(delta > epsilon);
        }
        other => panic!("Expected EpsilonViolation, got: {other}"),
    }
}

#[tokio::test]
async fn empty_batch_rejected() {
    let engine = AccountableRedaction::new(test_config(), RedactionVerifier::placeholder());
    let stats  = sample_stats();
    let result = engine.execute(&stats, vec![], 1_700_000_003).await;
    assert!(matches!(result, Err(RedactionError::EmptyBatch)));
}

#[tokio::test]
async fn commitment_pair_is_binding() {
    let stats_before = sample_stats();
    let entries = vec![make_entry("gender:female", false, 10)];
    let stats_after = stats_before.simulate_redaction(&entries);

    let com_before = StateCommitment::from_statistics(&stats_before);
    let com_after  = StateCommitment::from_statistics(&stats_after);

    assert_ne!(com_before.commitment_point, com_after.commitment_point,
        "Commitments must differ after redaction");
    assert!(com_before.verify(&stats_before));
    assert!(com_after.verify(&stats_after));
    assert!(!com_before.verify(&stats_after),
        "Commitment must not verify against wrong stats");
}
