
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use buildtovalue::kernel::validators::*;
use buildtovalue::kernel::evidence::TechnicalEvidence;
use std::time::Duration;

/// Benchmark: CPF Validation (constant-time)
fn bench_cpf_validation(c: &mut Criterion) {
    let validator = CPFValidator::new();
    
    let test_cases = vec![
        ("no_cpf", "Texto sem nenhum CPF aqui"),
        ("valid_cpf", "Meu CPF é 123.456.789-09"),
        ("invalid_cpf", "CPF inválido: 000.000.000-00"),
        ("multiple_cpf", "CPF1: 123.456.789-09 e CPF2: 987.654.321-00"),
    ];
    
    let mut group = c.benchmark_group("cpf_validation");
    group.measurement_time(Duration::from_secs(10));
    
    for (name, input) in test_cases {
        group.bench_with_input(BenchmarkId::new("constant_time", name), &input, |b, i| {
            b.iter(|| validator.validate_constant_time(black_box(i)))
        });
    }
    
    group.finish();
}

/// Benchmark: Evidence Protocol (finalization)
fn bench_evidence_finalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("evidence_protocol");
    
    // Cenário 1: Sem findings
    group.bench_function("finalize_empty", |b| {
        b.iter(|| {
            let mut evidence = TechnicalEvidence::new(0x1234);
            evidence.finalize().unwrap();
            black_box(evidence);
        })
    });
    
    // Cenário 2: 5 findings normais
    group.bench_function("finalize_5_findings", |b| {
        b.iter(|| {
            let mut evidence = TechnicalEvidence::new(0x1234);
            
            for i in 0..5 {
                evidence.add_finding(Finding::new(
                    ValidatorModule::CPF,
                    TechnicalSeverity::PolicyViolation,
                    &format!("FINDING_{}", i),
                    "Test finding",
                    "Description",
                ));
            }
            
            evidence.finalize().unwrap();
            black_box(evidence);
        })
    });
    
    // Cenário 3: 10 findings normais + 3 critical
    group.bench_function("finalize_10_normal_3_critical", |b| {
        b.iter(|| {
            let mut evidence = TechnicalEvidence::new(0x1234);
            
            // 10 normais
            for i in 0..10 {
                evidence.add_finding(Finding::new(
                    ValidatorModule::Entropy,
                    TechnicalSeverity::Low,
                    "LOW_FINDING",
                    "Low priority",
                    "...",
                ));
            }
            
            // 3 critical
            for i in 0..3 {
                evidence.add_finding(Finding::new(
                    ValidatorModule::CPF,
                    TechnicalSeverity::Critical,
                    "CRITICAL_FINDING",
                    "Critical",
                    "...",
                ));
            }
            
            evidence.finalize().unwrap();
            black_box(evidence);
        })
    });
    
    group.finish();
}

/// Benchmark: Ledger Operations
fn bench_ledger_operations(c: &mut Criterion) {
    use buildtovalue::kernel::ledger::*;
    use std::path::PathBuf;
    
    let mut group = c.benchmark_group("ledger");
    
    // Benchmark: Append to WAL
    group.bench_function("wal_append", |b| {
        let wal = WriteAheadLog::new(10000);
        let evidence = TechnicalEvidence::new(0x1234);
        let verdict = create_mock_verdict();
        let entry = LedgerEntry::new(1, 0x1234, &evidence, &verdict, 0);
        
        b.iter(|| {
            wal.append(black_box(entry.clone())).unwrap();
        })
    });
    
    // Benchmark: Hash calculation
    group.bench_function("entry_hash_calculation", |b| {
        let evidence = TechnicalEvidence::new(0x1234);
        let verdict = create_mock_verdict();
        let entry = LedgerEntry::new(1, 0x1234, &evidence, &verdict, 0);
        
        b.iter(|| {
            black_box(entry.calculate_hash());
        })
    });
    
    // Benchmark: Chain validation (100 entries)
    group.bench_function("validate_chain_100_entries", |b| {
        let entries = create_chain_of_entries(100);
        
        b.iter(|| {
            for i in 1..entries.len() {
                assert!(entries[i].validate_chain(&entries[i-1]));
            }
        })
    });
    
    group.finish();
}

/// Benchmark: End-to-End Request Processing
fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    group.measurement_time(Duration::from_secs(15));
    
    // Simula request completo: Input → Evidence → Verdict → Ledger
    group.bench_function("complete_request_pipeline", |b| {
        let kernel = RustSovereignKernel::new();
        let governance = PythonGovernanceLayer::new();
        
        let input = "Discussão médica: Paciente CPF 123.456.789-09";
        let context = create_mock_context();
        
        b.iter(|| {
            // 1. Rust Kernel: Scan
            let evidence = kernel.scan_for_evidence(black_box(input));
            
            // 2. Python Governance: Decide
            let verdict = governance.decide(black_box(&evidence), black_box(&context));
            
            // 3. Ledger: Append
            let entry = LedgerEntry::new(1, evidence.audit_trail_id, &evidence, &verdict, 0);
            // (Não persiste em benchmark, apenas cria)
            
            black_box(entry);
        })
    });
    
    group.finish();
}

/// Benchmark: Batch Processing (100 requests)
fn bench_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_processing");
    group.measurement_time(Duration::from_secs(20));
    
    let inputs: Vec<String> = (0..100)
        .map(|i| format!("Request {}: CPF 123.456.{:03}-09", i, i))
        .collect();
    
    group.bench_function("batch_100_requests", |b| {
        let kernel = RustSovereignKernel::new();
        
        b.iter(|| {
            let evidences = kernel.batch_scan(black_box(&inputs), 10);
            black_box(evidences);
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_cpf_validation,
    bench_evidence_finalization,
    bench_ledger_operations,
    bench_end_to_end,
    bench_batch_processing,
);

criterion_main!(benches);