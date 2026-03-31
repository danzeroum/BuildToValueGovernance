use criterion::{criterion_group, criterion_main, Criterion, black_box};
use btv_redaction::{GroupStats, LedgerStatistics, state_commitment::StateCommitment};

fn large_stats(decisions_per_group: u64, n_groups: usize) -> LedgerStatistics {
    LedgerStatistics {
        groups: (0..n_groups)
            .map(|i| GroupStats {
                group_label: format!("group:{i}"),
                total:        decisions_per_group,
                approved:     decisions_per_group * 4 / 5,
                denied:       decisions_per_group / 5,
                redacted:     0,
            })
            .collect(),
        total_decisions: decisions_per_group * n_groups as u64,
        timestamp: 1_700_000_000,
    }
}

fn bench_commitment_100k(c: &mut Criterion) {
    let stats = large_stats(10_000, 10);
    c.bench_function("redaction::StateCommitment::from_statistics (100K)", |b| {
        b.iter(|| StateCommitment::from_statistics(black_box(&stats)))
    });
}

criterion_group!(benches, bench_commitment_100k);
criterion_main!(benches);
