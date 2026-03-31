//! Benchmarks for btv-governance hot paths.
//! Target: MandateToken::is_live() < 0.1ms, verify_tripartite_signatures < 1ms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use btv_governance::{
    mandate::{AmendmentId, MandateToken, RatificationProof},
    ratification::verify_tripartite_signatures,
};
use chrono::{Duration, Utc};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_bench_mandate() -> (MandateToken, RatificationProof) {
    let leg  = SigningKey::generate(&mut OsRng);
    let jud  = SigningKey::generate(&mut OsRng);
    let exec = SigningKey::generate(&mut OsRng);

    let nonce: [u8; 32] = [42u8; 32];
    let ts = Utc::now();

    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(b"GENESIS\x00");
    msg.extend_from_slice(&nonce);
    msg.extend_from_slice(&ts.timestamp().to_le_bytes());

    let proof = RatificationProof {
        amendment:            AmendmentId::Genesis,
        legislative_sig:      leg.sign(&msg).to_bytes(),
        judicial_sig:         jud.sign(&msg).to_bytes(),
        executive_rep_sig:    exec.sign(&msg).to_bytes(),
        nonce,
        timestamp: ts,
        legislative_pubkey:   leg.verifying_key().to_bytes(),
        judicial_pubkey:      jud.verifying_key().to_bytes(),
        executive_rep_pubkey: exec.verifying_key().to_bytes(),
    };

    let mandate = MandateToken::new(0, Utc::now() + Duration::days(30), proof.clone());
    (mandate, proof)
}

// ── benchmarks ───────────────────────────────────────────────────────────────

fn bench_mandate_is_live(c: &mut Criterion) {
    let (mandate, _) = make_bench_mandate();
    c.bench_function("governance::MandateToken::is_live", |b| {
        b.iter(|| black_box(mandate.is_live()))
    });
}

fn bench_mandate_borrow_live(c: &mut Criterion) {
    let (mandate, _) = make_bench_mandate();
    c.bench_function("governance::MandateToken::borrow_live", |b| {
        b.iter(|| black_box(mandate.borrow_live().is_ok()))
    });
}

fn bench_tripartite_verify(c: &mut Criterion) {
    let (_, proof) = make_bench_mandate();
    c.bench_function("governance::verify_tripartite_signatures", |b| {
        b.iter(|| black_box(verify_tripartite_signatures(&proof)))
    });
}

fn bench_mandate_hash(c: &mut Criterion) {
    let (mandate, _) = make_bench_mandate();
    c.bench_function("governance::MandateToken::hash", |b| {
        b.iter(|| black_box(mandate.hash()))
    });
}

fn bench_mandate_to_wire(c: &mut Criterion) {
    let (mandate, _) = make_bench_mandate();
    c.bench_function("governance::MandateToken::to_wire", |b| {
        b.iter(|| black_box(mandate.to_wire()))
    });
}

criterion_group!(
    benches,
    bench_mandate_is_live,
    bench_mandate_borrow_live,
    bench_tripartite_verify,
    bench_mandate_hash,
    bench_mandate_to_wire,
);
criterion_main!(benches);
