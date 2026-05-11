#![allow(clippy::unwrap_used)]
use criterion::{criterion_group, criterion_main, Criterion, black_box};
use btv_judicial::HmacVerifier;
use btv_types::{Blake3Hash, Decision, VerdictRecord};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const BENCH_KEY: &[u8] = b"bench-hmac-key-for-criterion!!";

fn make_verdict() -> VerdictRecord {
    let mut mac = HmacSha256::new_from_slice(BENCH_KEY).unwrap();
    mac.update(&[0x01; 32]);
    mac.update(&[0u8]);
    mac.update(&[0x02; 32]);
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    VerdictRecord {
        evidence_hash:       Blake3Hash([0x01; 32]),
        decision:            Decision::Allow,
        explanation_hash:    Blake3Hash([0x02; 32]),
        hmac_tag:            tag,
        legislative_version: 1,
    }
}

fn bench_hmac_verify(c: &mut Criterion) {
    let verifier = HmacVerifier::new(BENCH_KEY.to_vec());
    let verdict  = make_verdict();
    c.bench_function("judicial::hmac_verify", |b| {
        b.iter(|| black_box(verifier.verify(black_box(&verdict))))
    });
}

criterion_group!(benches, bench_hmac_verify);
criterion_main!(benches);
