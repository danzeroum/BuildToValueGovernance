# ADR-0090: Fairness Pipeline Performance Validation

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `rust/gateway/benches/fairness_pipeline.rs` (estende), nota
             em ADR-0088 §D2 (marca schema como `v1alpha` até estabilização).
**Pré-requisitos**: ADR-0086, ADR-0087, ADR-0088, ADR-0089 (todos em main)

---

## Contexto

ADR-0088 §D1 decidiu que o cálculo do PSI deve ser **síncrono inline** a
cada 500 transações, rejeitando `tokio::task::spawn_blocking`. A
justificativa: *"PSI sobre 10 bins é sub-milissegundo (10 multiplicações
+ 10 logaritmos)"*. Esta é uma **hipótese**, não evidência.

ADR-0089 §D4 já registrou que essa hipótese precisa ser validada por
benchmark com critério explícito: *"P99(B) ≤ P99(A) + 5ms → D1 ADR-0088
confirmado"*. O bench atual em `benches/fairness_pipeline.rs`
(commit `dc0d32b`) cobre 5 cenários **single-thread**, suficientes para
isolar o custo da composição matemática mas insuficientes para capturar
o risco real de produção: **contenção no `RwLock<HashMap<tenant, _>>`
quando dezenas de tenants atingem a janela de recompute simultaneamente**
(*thundering herd*).

ADR-0090 fecha o ciclo de validação: estende o bench com cenário
multi-tenant concorrente, define o critério de decisão binária, e
documenta o caveat de hardware antes de iniciar a sprint de gRPC
`AuditExposer`.

---

## Decisões

### D1 — Critério de decisão binária

**Regra explícita:**

```
P99(B_concurrent) ≤ P99(A_baseline) + 5ms
  → ADR-0088 §D1 (síncrono inline) CONFIRMADO. Nenhuma mudança de código.

P99(B_concurrent) > P99(A_baseline) + 5ms
  → ADR-0088 §D1 INVALIDADO. Abrir ADR-0091 (perf hardening) com
    variante `JonasMonitor::record_async` despachando via
    `tokio::task::spawn_blocking`. Hot path lê AtomicBool
    `is_drift_critical.load(Ordering::Relaxed)`.
```

**Crítico — qual cenário B usar:**
- `B_concurrent` (multi-tenant, thundering herd) é o critério de produção.
- `B_record_steady_state` e `B_record_at_compute_boundary_batch_500`
  (cenários single-thread já em main) são linha de base **interna** —
  úteis para isolar o custo da matemática vs. o custo da contenção. Não
  são o critério de decisão.

O risco real de produção não é o `compute_psi` em isolado (sub-ms,
já demonstrado). É a contenção do `RwLock<HashMap<tenant_id,
TenantJonasState>>` quando dezenas de tenants atingem a janela de
recompute na mesma fatia de tempo de scheduler.

### D2 — Caveat container vs. hardware-prod

Bench roda no container CI / dev. Hardware de produção é heterogêneo
(VM EC2, on-prem, BYO infra). **Valores absolutos** medidos no bench
não são SLA de produção.

**A métrica relevante é a razão `P99(B_concurrent) / P99(A_baseline)`**,
que é hardware-invariante para workloads CPU-bound sem I/O (variação
< 5% empiricamente). Isso permite que a evidência colhida em qualquer
hardware razoavelmente moderno seja indicativa.

Operadores que rodam em hardware atípico (ARM, hipervisores antigos,
contentores com CPU throttled) **devem rerodar o bench em seu hardware
real antes de produção** e revalidar o critério D1.

O ADR-0090 documenta o trade-off explicitamente — não pretende
substituir benchmarking operacional, apenas estabelecer linha de base
arquitetural reprodutível.

### D3 — Marcação `v1alpha` no schema `FairnessDecision` (ADR-0088 §D2)

Antes do gRPC `AuditExposer` consumir o schema, ADR-0088 §D2 é
**explicitamente marcado como `v1alpha`** durante a janela de validação
(este ADR + bench + eventual ADR-0091). Campos novos podem ser
adicionados durante essa janela conforme ADR-0082 (Option<T> +
`#[serde(default)]`).

Parceiros Java integrando antes da estabilização (ADR-0085) devem
prefixar consumidores com `v1alpha`. Após decisão binária do D1 deste
ADR + merge de eventual ADR-0091, o schema transita para `v1` estável.

Esta marcação é aplicada como nota em ADR-0088 §D2 neste commit, sem
mudança de código (1 linha no documento existente).

### D4 — Harness do bench concorrente

Cenário `B_concurrent` (novo, este ADR):

```rust
// N_TENANTS = 16 (alinhado com tenants típicos por instância)
// N_THREADS = 32 (sobrescrição típica do Tokio multi-thread runtime)
// Cada thread alterna entre 8 tenants distintos
// JONAS_COMPUTE_INTERVAL records por tenant → todos atingem recompute
//   na mesma janela
fn bench_concurrent_boundary(c: &mut Criterion) {
    let state = bench_state_with_tenants(N_TENANTS);
    c.bench_function("B_concurrent_thundering_herd", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..N_THREADS).map(|t| {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    for i in 0..JONAS_COMPUTE_INTERVAL {
                        let tenant = format!("bench-{}", (t + i as usize) % N_TENANTS);
                        state.jonas_monitor.record(&tenant, 0.5, false);
                    }
                })
            }).collect();
            for h in handles { h.join().unwrap(); }
        });
    });
}
```

Hipótese a falsificar: *"a contenção no `RwLock<HashMap<tenant,
TenantJonasState>>` não vira gargalo dominante quando dezenas de tenants
disparam recompute na mesma janela"*.

Se a hipótese for refutada (P99 spike > 5ms), o ADR-0091 deve
considerar não apenas `spawn_blocking` mas também:
- Substituir `RwLock<HashMap>` por `DashMap` (lockless reads)
- Mover `Mutex<VecDeque>` interno para `parking_lot::Mutex` (menos overhead)
- Pre-sharding por hash(tenant_id) % N_SHARDS

ADR-0091 fica para esses detalhes; ADR-0090 apenas constata.

---

## Procedimento de execução

1. Estender `benches/fairness_pipeline.rs` com `bench_concurrent_boundary`
   (este commit).
2. Rodar `cargo bench -p btv-gateway --bench fairness_pipeline` no
   container CI. Capturar HTML reports em `target/criterion/`.
3. Documentar P99 numérico de cada cenário neste ADR (seção "Resultados"
   abaixo, atualizada após execução).
4. Aplicar D1 — decisão binária:
   - ✅ Confirma → fechar ADR-0090, prosseguir para gRPC AuditExposer.
   - ❌ Refuta → abrir ADR-0091, refactor antes de gRPC AuditExposer.

---

## Resultados (a preencher pós-execução)

**Hardware**: TBD (CI container)
**Runtime**: Tokio multi-thread, default worker count

| Cenário | P99 | Mediana | Stddev |
|---|---|---|---|
| A_mode_for_disabled | TBD | TBD | TBD |
| B_record_steady_state | TBD | TBD | TBD |
| B_record_at_compute_boundary | TBD | TBD | TBD |
| **B_concurrent_thundering_herd** | TBD | TBD | TBD |
| compose_fairness_critical_both | TBD | TBD | TBD |
| compose_fairness_nominal | TBD | TBD | TBD |

**Razão `P99(B_concurrent) / P99(A_baseline)`**: TBD

**Decisão D1**: TBD (aplicar regra binária acima)

---

## Out-of-scope

- ADR-0091 (`spawn_blocking` variant) — apenas se D1 refutar.
- Bench de cenários degradados (lock poison recovery, slow disk).
- Otimizações de `compose_fairness_action` — já provadamente sub-ms.
- Webhooks de alerta para regressão automatizada de bench — ops, não
  arquitetura.

---

## Referências

- ADR-0086 — Rawls DIR Engine
- ADR-0087 — Jonas PSI Engine (§D5 — `Mutex<VecDeque>` por tenant)
- ADR-0088 — Gatekeeper Pipeline Wiring (§D1 síncrono — validado aqui)
- ADR-0089 — Fairness Observability Loop (§D4 — bench triggers)
- Criterion.rs documentation (`iter_batched`, multi-thread benchmarks)
