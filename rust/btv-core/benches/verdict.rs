use criterion::{black_box, criterion_group, criterion_main, Criterion};
use btv_core::{
    ComplianceAuthority, ComplianceError, ComplianceRegistry,
    Decision, EvidenceToken, Verdict,
};

struct BenchRegistry;
impl ComplianceRegistry for BenchRegistry {
    fn validate(&self, _j: &str, _p: &str) -> Result<u32, ComplianceError> {
        Ok(720)
    }
}

fn bench_verdict_new(c: &mut Criterion) {
    std::env::set_var("BTV_HMAC_KEY", "bench-key");
    let authority = ComplianceAuthority::new(Box::new(BenchRegistry));
    let context_4kb = vec![0x42u8; 4096];

    c.bench_function("Verdict::new (4KB context)", |b| {
        b.iter(|| {
            let evidence = EvidenceToken::new(black_box(&context_4kb));
            let compliance = authority.issue("BR", "LGPD-v1").unwrap();
            let verdict = Verdict::new(evidence, compliance, Decision::Allow, "approved".to_string());
            black_box(verdict);
        })
    });
}

fn bench_verify_integrity(c: &mut Criterion) {
    std::env::set_var("BTV_HMAC_KEY", "bench-key");
    let authority = ComplianceAuthority::new(Box::new(BenchRegistry));
    let evidence = EvidenceToken::new(&[0x42u8; 64]);
    let compliance = authority.issue("BR", "LGPD-v1").unwrap();
    let verdict = Verdict::new(evidence, compliance, Decision::Allow, "test".to_string());

    c.bench_function("Verdict::verify_integrity", |b| {
        b.iter(|| black_box(verdict.verify_integrity()))
    });
}

criterion_group!(benches, bench_verdict_new, bench_verify_integrity);
criterion_main!(benches);
