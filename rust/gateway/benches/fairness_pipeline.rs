//! ADR-0089 §D4 — Benchmark do pipeline fairness.
//!
//! Mede o overhead de cada estágio do `apply_fairness` na latência da
//! transação, com três objetivos:
//!
//! 1. **Validar D1 ADR-0088** (síncrono inline). Critério explícito:
//!    P99(record_at_boundary) ≤ P99(record_steady_state) + 5ms na
//!    carga típica. Se o spike na transação N=500 ultrapassar 5ms,
//!    reverter para `tokio::task::spawn_blocking` torna-se justificável.
//!
//! 2. **Estabelecer linha de baseline** (`mode_for_disabled`) para que
//!    o overhead seja comparável em PRs futuras (regressão de
//!    performance vira sinal).
//!
//! 3. **Isolar custo da composição** (`compose_fairness_action`)
//!    independente do storage — função pura, deve ser sub-microssegundo.
//!
//! Cenário C (hipotético spawn_blocking) **NÃO está implementado** —
//! exigiria criar uma variante de `JonasMonitor::record` que despacha
//! para `tokio::task::spawn_blocking`. Fica para ADR-0090 (perf
//! hardening) se os benchmarks aqui mostrarem que o spike síncrono é
//! intolerável.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use btv_gateway::fairness_mode::FairnessMode;
use btv_gateway::state::AppState;
use buildtovalue_kernel::core::types::Action;
use buildtovalue_kernel::statistics::{
    compose_fairness_action, DriftAlert, FairnessMetrics, GroupClass,
    JonasBaselineLoader, OutcomeBucket, DEFAULT_DIR_THRESHOLD,
    JONAS_COMPUTE_INTERVAL,
};

const BASELINE_YAML: &str = r#"
version: "1.0.0"
model_id: "bench-model"
bins: 10
reference_proportions:
  - 0.05
  - 0.07
  - 0.10
  - 0.13
  - 0.15
  - 0.18
  - 0.15
  - 0.10
  - 0.05
  - 0.02
"#;

/// AppState com baseline instalado para o tenant `"bench"` e mode
/// Enforced. Usado para benches que exercitam o caminho completo.
fn bench_state() -> Arc<AppState> {
    let state = Arc::new(AppState::new());
    state
        .fairness_modes
        .install("bench", FairnessMode::Enforced);
    let baseline = JonasBaselineLoader::from_yaml_str(BASELINE_YAML)
        .expect("baseline parse");
    state.jonas_monitor.install_baseline("bench", baseline);
    state
}

/// Cenário A (baseline): apenas resolver `FairnessMode::Disabled` no
/// hot path quando o pipeline está completamente desligado. Estabelece
/// o piso de overhead que qualquer alternativa precisa bater.
fn bench_mode_for_disabled(c: &mut Criterion) {
    let state = Arc::new(AppState::new()); // sem installs → Disabled default
    c.bench_function("A_mode_for_disabled", |b| {
        b.iter(|| {
            black_box(state.fairness_mode_for(black_box("any-tenant")));
        });
    });
}

/// Cenário B-steady: `JonasMonitor::record` longe do boundary
/// (transação N=1, N=2, ...). Mede o custo amortizado de cada record
/// individual sem recompute.
fn bench_record_steady_state(c: &mut Criterion) {
    let state = bench_state();
    c.bench_function("B_record_steady_state", |b| {
        b.iter(|| {
            state.jonas_monitor.record(black_box("bench"), black_box(0.5), false);
            state
                .rawls_monitor
                .record(black_box("bench"), GroupClass::Privileged, OutcomeBucket::Favorable);
        });
    });
}

/// Cenário B-boundary: força a transação N=500 que dispara o recompute
/// inline. Cada iteração:
///   1. Preenche 499 records sem compute
///   2. O record #500 dispara `histogram_from_scores` + `compute_psi`
///
/// O bench reporta o **tempo total** do batch — divida por 500 para
/// custo médio. O spike isolado é a diferença entre este valor médio
/// e o `B_record_steady_state`.
fn bench_record_at_compute_boundary(c: &mut Criterion) {
    c.bench_function("B_record_at_compute_boundary_batch_500", |b| {
        b.iter_batched(
            // Setup: estado fresco por iteração para o contador atômico
            // estar em 0 e o record #500 disparar o recompute.
            bench_state,
            |state| {
                for i in 0..JONAS_COMPUTE_INTERVAL {
                    let score = ((i as f64) % 10.0) / 10.0 + 0.05;
                    state.jonas_monitor.record("bench", score, false);
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// `compose_fairness_action` puro — sem RwLock, sem buffer access.
/// Estabelece o piso teórico do custo da composição.
fn bench_compose_fairness_action(c: &mut Criterion) {
    let rawls = FairnessMetrics {
        dir: 0.5,
        privileged_favorable_rate: 0.9,
        unprivileged_favorable_rate: 0.45,
        insufficient_samples: false,
        violates_threshold: true,
        threshold_used: DEFAULT_DIR_THRESHOLD,
    };
    c.bench_function("compose_fairness_critical_both", |b| {
        b.iter(|| {
            let decision = compose_fairness_action(
                black_box(Action::Allow),
                black_box(&rawls),
                black_box(DriftAlert::Critical),
            );
            black_box(decision);
        });
    });
}

/// Variante `compose_fairness_action` no caminho feliz (nenhuma
/// violação). Útil porque a maioria das chamadas em produção segue
/// este caminho — o "Critical+Critical" é raro.
fn bench_compose_fairness_action_happy(c: &mut Criterion) {
    let rawls = FairnessMetrics {
        dir: 1.0,
        privileged_favorable_rate: 0.9,
        unprivileged_favorable_rate: 0.9,
        insufficient_samples: false,
        violates_threshold: false,
        threshold_used: DEFAULT_DIR_THRESHOLD,
    };
    c.bench_function("compose_fairness_nominal", |b| {
        b.iter(|| {
            let decision = compose_fairness_action(
                black_box(Action::Allow),
                black_box(&rawls),
                black_box(DriftAlert::Nominal),
            );
            black_box(decision);
        });
    });
}

/// **ADR-0090 D4 — Cenário B-concurrent (thundering herd).**
///
/// Critério oficial de validação do D1 do ADR-0088. Simula 32 threads
/// (sobrescrição típica do Tokio multi-thread runtime) escrevendo em
/// 16 tenants distintos, todos atingindo `JONAS_COMPUTE_INTERVAL` na
/// mesma janela. Mede o tail-latency causado pela contenção do
/// `RwLock<HashMap<tenant, TenantJonasState>>` quando dezenas de
/// tenants disparam recompute concorrentemente.
///
/// Hipótese a falsificar: a contenção do RwLock global não vira gargalo
/// dominante. Se P99(este bench) > P99(A_baseline) + 5ms, ADR-0091
/// (perf hardening) deve ser aberto.
const N_TENANTS: usize = 16;
const N_THREADS: usize = 32;

fn bench_state_with_n_tenants(n: usize) -> Arc<AppState> {
    let state = Arc::new(AppState::new());
    let baseline_template = JonasBaselineLoader::from_yaml_str(BASELINE_YAML)
        .expect("baseline parse");
    for i in 0..n {
        let tenant = format!("bench-{i}");
        state.fairness_modes.install(&tenant, FairnessMode::Enforced);
        state.jonas_monitor.install_baseline(&tenant, baseline_template.clone());
    }
    state
}

fn bench_concurrent_boundary(c: &mut Criterion) {
    let state = bench_state_with_n_tenants(N_TENANTS);
    c.bench_function("B_concurrent_thundering_herd", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..N_THREADS)
                .map(|t| {
                    let state = Arc::clone(&state);
                    std::thread::spawn(move || {
                        for i in 0..JONAS_COMPUTE_INTERVAL {
                            let tenant_idx = (t + i as usize) % N_TENANTS;
                            let tenant = format!("bench-{tenant_idx}");
                            let score = ((i as f64) % 10.0) / 10.0 + 0.05;
                            state.jonas_monitor.record(&tenant, score, false);
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("thread panicked");
            }
        });
    });
}

criterion_group!(
    benches,
    bench_mode_for_disabled,
    bench_record_steady_state,
    bench_record_at_compute_boundary,
    bench_concurrent_boundary,
    bench_compose_fairness_action,
    bench_compose_fairness_action_happy,
);
criterion_main!(benches);
