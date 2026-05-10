// Arquivo: rust/kernel/benches/kernel_bench.rs
//
// Benchmark Criterion — BuildToValue Kernel v1.0
// Mede latência do hot path com todos os módulos registrados.
// Target: < 30ms p99 (Rust kernel)
//
// Execução:  cargo bench -p buildtovalue-kernel
// Relatório: target/criterion/report/index.html

use criterion::{
    black_box, criterion_group, criterion_main,
    Criterion, BatchSize, Throughput,
};
use std::time::Duration;

use buildtovalue_kernel::Gatekeeper;
use buildtovalue_kernel::evidence::{TechnicalEvidence, Finding};
use buildtovalue_kernel::core::types::TechnicalSeverity;
use buildtovalue_kernel::ValidatorModule;

// ═══════════════════════════════════════════════════════════════
// GRUPO 1: Gatekeeper Pipeline Completo (hot path principal)
// ═══════════════════════════════════════════════════════════════

fn bench_gatekeeper_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("gatekeeper_pipeline");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(200);

    // --- Cenário 1: Input limpo (nenhum finding) ---
    group.bench_function("clean_input", |b| {
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box("Hello, this is a normal message."),
                    black_box(0x1001),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    // --- Cenário 2: CPF direto (critical finding) ---
    group.bench_function("cpf_direct", |b| {
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box("Meu CPF é 123.456.789-09"),
                    black_box(0x2002),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    // --- Cenário 3: Múltiplos PII (CPF + Email + Phone) ---
    group.bench_function("multi_pii", |b| {
        let input = "CPF 123.456.789-09, email test@example.com, \
                      tel +55 11 99999-8888";
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box(input),
                    black_box(0x3003),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    // --- Cenário 4: Base64-encoded CPF (deobfuscation + rescan) ---
    group.bench_function("base64_cpf_rescan", |b| {
        // "123.456.789-09" em Base64
        let input = "hidden: MTIzLjQ1Ni43ODktMDk=";
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box(input),
                    black_box(0x4004),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    // --- Cenário 5: Input longo (1KB) ---
    group.bench_function("long_input_1kb", |b| {
        let input = "A".repeat(1024);
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box(&input),
                    black_box(0x5005),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    // --- Cenário 6: SQL injection pattern ---
    group.bench_function("sql_injection", |b| {
        let input = "Robert'; DROP TABLE users;--";
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box(input),
                    black_box(0x6006),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    // --- Cenário 7: Leetspeak encoded ---
    group.bench_function("leetspeak_encoded", |b| {
        let input = "s3nd m3 y0ur p4ssw0rd pl34s3";
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box(input),
                    black_box(0x7007),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    // --- Cenário 8: Adversarial — 10KB com PII denso (p99 real) ---
    group.bench_function("adversarial_10kb_dense_pii", |b| {
        let chunk = "CPF 123.456.789-09 email a@b.com \
                      CC 4111111111111111 tel +5511999998888 ";
        let input = chunk.repeat(130); // ~10KB
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                let _ = black_box(gk.scan_for_evidence(
                    black_box(&input),
                    black_box(0x8008),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════
// GRUPO 2: Evidence Protocol (finalization isolada)
// ═══════════════════════════════════════════════════════════════

fn bench_evidence_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("evidence_protocol");
    group.measurement_time(Duration::from_secs(8));

    // --- Finalize vazia (overhead puro: hash + metadata) ---
    group.bench_function("finalize_empty", |b| {
        b.iter(|| {
            let mut ev = TechnicalEvidence::new(black_box(0xAAAA));
            let _ = ev.finalize();
            black_box(&ev);
        });
    });

    // --- Finalize com 10 findings sintéticos ---
    group.bench_function("finalize_10_findings_isolated", |b| {
        b.iter(|| {
            let mut ev = TechnicalEvidence::new(black_box(0xBBBB));
            for _ in 0..10 {
                ev.add_finding(Finding::new(
                    ValidatorModule::CPF,
                    TechnicalSeverity::PolicyViolation,
                    "BENCH_FINDING",
                    "Benchmark synthetic finding",
                    "benchmark",
                ));
            }
            let _ = ev.finalize();
            black_box(&ev);
        });
    });

    // --- Finalize com 3 critical ---
    group.bench_function("finalize_3_critical_isolated", |b| {
        b.iter(|| {
            let mut ev = TechnicalEvidence::new(black_box(0xCCCC));
            for _ in 0..3 {
                ev.add_finding(Finding::new(
                    ValidatorModule::CPF,
                    TechnicalSeverity::Critical(0),
                    "CRITICAL_BENCH",
                    "Critical benchmark finding",
                    "benchmark",
                ));
            }
            let _ = ev.finalize();
            black_box(&ev);
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════
// GRUPO 3: Throughput (requests/segundo)
// ═══════════════════════════════════════════════════════════════

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.measurement_time(Duration::from_secs(15));

    let inputs: Vec<&str> = vec![
        "Clean message, no PII here.",
        "CPF: 123.456.789-09",
        "Email: user@example.com",
        "Tel: +55 11 99999-8888",
        "CNPJ: 11.222.333/0001-81",
        "Credit card: 4111 1111 1111 1111",
        "Base64 hidden: dGVzdEBleGFtcGxlLmNvbQ==",
        "Normal text with some entropy!@#$%",
        "Robert'; DROP TABLE users;--",
        "A medical discussion about patient care",
    ];

    group.throughput(Throughput::Elements(inputs.len() as u64));

    group.bench_function("mixed_10_requests", |b| {
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                for (i, input) in inputs.iter().enumerate() {
                    let _ = black_box(gk.scan_for_evidence(
                        black_box(input),
                        black_box(i as u128),
                    ));
                }
            },
            BatchSize::SmallInput,
        );
    });

    // Bulk 100 com CPF
    let bulk: Vec<String> = (0..100)
        .map(|i| format!("Request {}: CPF 123.456.{:03}-09", i, i % 1000))
        .collect();
    group.throughput(Throughput::Elements(100));

    group.bench_function("bulk_100_cpf", |b| {
        b.iter_batched(
            || Gatekeeper::new(),
            |mut gk| {
                for (i, input) in bulk.iter().enumerate() {
                    let _ = black_box(gk.scan_for_evidence(
                        black_box(input.as_str()),
                        black_box(i as u128),
                    ));
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════
// REGISTRO
// ═══════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_gatekeeper_pipeline,
    bench_evidence_protocol,
    bench_throughput,
);

criterion_main!(benches);
