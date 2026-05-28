# ADR-0089: Fairness Observability Loop

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta (decisões reconciliadas com revisões consolidadas)
**Impacto**: `rust/gateway/src/main.rs`, `rust/gateway/src/state.rs`,
             `rust/gateway/src/routes/internal.rs` (novo),
             `rust/gateway/src/tenant_status.rs` (novo),
             `rust/kernel/src/statistics/{rawls,jonas_monitor}.rs`,
             `rust/kernel/src/ledger/tenant_router.rs`, `policies/` (novo),
             `rust/gateway/benches/fairness_pipeline.rs` (novo)
**Pré-requisitos**: ADR-0083 (TenantStorageRouter), ADR-0086 (Rawls),
                    ADR-0087 (Jonas), ADR-0088 (Pipeline Wiring)

---

## Contexto

Após ADR-0088, o pipeline fairness está wireado mas **inerte em produção real**:
- `JonasMonitor` exige `install_baseline()` explícito antes de qualquer
  `record()` — sem boot step, todo tenant fica `Disabled` para Jonas.
- `FairnessModeRegistry` requer `install()` explícito — sem boot step,
  todo tenant cai no default `Disabled` (sem fairness).
- Não há mecanismo para o DPO atualizar baseline sem reinício do gateway.
- Tenants removidos do `TenantStorageRouter` deixam entradas órfãs nos
  monitores indefinidamente (ADR-0088 §D4 deferiu cleanup eager).
- Não há benchmark validando a decisão D1 do ADR-0088 (síncrono inline
  vs `tokio::spawn_blocking`).

ADR-0089 fecha o ciclo operacional: boot step de policies, recarga sob
demanda, cleanup eager por lifecycle, e evidência empírica para
decisões de performance.

---

## Layout de filesystem

```
policies/
├── {tenant_id}/
│   ├── drift_baseline.yaml     # ADR-0087: baseline Jonas (DPO-approved)
│   └── fairness.yaml           # ADR-0088: mode (disabled|shadow|enforced)
└── ...
```

`policies/` mora na raiz do repo em dev/test; em produção, path absoluto
configurável via env `BTV_POLICIES_DIR` (default `/etc/btv/policies`).

`fairness.yaml` schema mínimo:

```yaml
mode: enforced   # disabled | shadow | enforced
```

`drift_baseline.yaml` schema já definido em ADR-0087 §D2.

**Validação no boot:** tenant com **apenas** `fairness.yaml` mas sem
`drift_baseline.yaml` → `TenantStatus::Degraded(MissingBaseline)`.
Tenant com YAML malformado → `TenantStatus::Degraded(InvalidBaseline)`.

---

## Decisões

### D1 — Boot step híbrido, com estado runtime separado da config

**Boot step:** `AppState::warm_policies(policies_dir).await` chamado em
`main.rs` **antes** de `axum::serve`. Carrega todos os tenants
declarados em `policies/`:

1. Walk diretório `policies/{tenant_id}/`.
2. Para cada tenant, parse `fairness.yaml` → `FairnessMode`, install no
   registry.
3. Parse `drift_baseline.yaml` → `JonasBaseline`, install no monitor.
4. Marcar tenant como `TenantStatus::Active` em caso de sucesso, ou
   `TenantStatus::Degraded(cause)` em falha.

**Tarefas em background (`tokio::spawn`)**: o boot step **não** é
necessariamente sequencial — tenants são carregados em paralelo via
`futures::join_all`. **Não** há `spawn` no hot path (D1 ADR-0088
preservado); o `spawn` aqui é apenas no boot, antes de aceitar tráfego.

**Separação config vs runtime — explícita:**

```rust
// gateway/src/fairness_mode.rs (já existe — config declarada, imutável)
pub enum FairnessMode {
    Disabled, Shadow, Enforced,
}

// gateway/src/tenant_status.rs (NOVO — estado runtime, mutável)
pub enum TenantStatus {
    /// Boot step ainda processando este tenant. Fail-soft: REDACT.
    Initializing,
    /// Baseline + fairness.yaml carregados com sucesso.
    Active,
    /// Falha de carregamento; outros tenants não afetados.
    Degraded(DegradationCause),
}

pub enum DegradationCause {
    MissingBaseline,
    InvalidBaseline(String),  // mensagem do BaselineError
    InvalidFairnessYaml(String),
    BaselineHashMismatch,     // futuro E162 (ADR-0087 Fase 2)
}
```

São ortogonais: tenant pode ter `FairnessMode::Enforced` E
`TenantStatus::Degraded(InvalidBaseline)` simultaneamente — handler
verifica **ambos**:

| FairnessMode | TenantStatus | Comportamento no `decide_handler` |
|---|---|---|
| `Disabled` | qualquer | Pipeline fairness skip total |
| `Shadow`/`Enforced` | `Initializing` | Fail-soft: REDACT com `governance_errors=[fairness_loading]` |
| `Shadow`/`Enforced` | `Active` | Pipeline completo (apply_fairness) |
| `Shadow`/`Enforced` | `Degraded(c)` | Fail-soft: REDACT + governance_errors contendo a causa |

`TenantStatus` vive no **gateway** (junto com `FairnessModeRegistry`),
não no kernel — é estado de orquestração HTTP, não de domínio fairness.

**Observabilidade obrigatória:**
- `tracing::error!` para cada falha de carregamento (nunca silencioso).
- Métrica Prometheus `btv_baseline_load_failures_total{tenant_id,cause}`.
- Métrica `btv_tenant_status{tenant_id,status}` (gauge).

### D2 — Endpoints internos autenticados via header em tempo constante

Dois endpoints em `/internal/v1/`:

```
POST   /internal/v1/reload-policy/{tenant_id}   → recarrega Jonas + Rawls + fairness.yaml
DELETE /internal/v1/tenants/{tenant_id}         → cleanup eager
```

**Autenticação:** header `X-BTV-Internal-Key` comparado com
`BTV_INTERNAL_SECRET` (env, mínimo 32 bytes / 256 bits). Comparação via
`constant_time_eq` (já usado em outros pontos do kernel) — sem timing
side-channel.

Layer Tower dedicado (`InternalAuthLayer`), aplicado **apenas** às rotas
`/internal/v1/*`. Ausente ou inválido → HTTP 401 sem corpo informativo
(menos sinal para enumeração de chaves).

**Trait comum no kernel** (entrega do commit 2):

```rust
// rust/kernel/src/statistics/reloadable.rs (NOVO)
pub trait ReloadableGuardrail: Send + Sync {
    /// Recarrega o estado do tenant a partir do conteúdo YAML fornecido
    /// pelo gateway (kernel não conhece filesystem — gateway lê o arquivo
    /// e passa o conteúdo). Retorna erro se YAML inválido.
    fn reload_baseline(&self, tenant_id: &str, yaml_content: &str)
        -> Result<(), ReloadError>;

    /// Remove o tenant. Idempotente — chamadas repetidas são noop.
    fn remove_tenant(&self, tenant_id: &str);
}

pub enum ReloadError {
    InvalidYaml(String),
    NotApplicable, // p.ex. Rawls não tem baseline YAML — `reload_baseline` é noop
}
```

**`RawlsMonitor`:** implementação trivial. `reload_baseline` retorna
`Err(NotApplicable)` (não há baseline YAML para Rawls; apenas o
threshold global, que é compile-time). `remove_tenant` faz
`HashMap::remove` em `counters`.

**`JonasMonitor`:** `reload_baseline` parsea YAML via
`JonasBaselineLoader`, faz `install_baseline()` (substitui se existir).
`remove_tenant` faz `HashMap::remove` em `tenants`.

**Operacional do endpoint reload-policy:**

```
1. Auth via X-BTV-Internal-Key (timing-safe)
2. Validar tenant_id via validate_tenant_id (ADR-0083 §D1)
3. Marcar TenantStatus::Initializing
4. Ler policies/{tenant_id}/drift_baseline.yaml (gateway-side I/O)
5. jonas_monitor.reload_baseline(tenant_id, yaml_content)
6. rawls_monitor.reload_baseline(tenant_id, "") → NotApplicable (noop OK)
7. Ler policies/{tenant_id}/fairness.yaml
8. fairness_modes.install(tenant_id, parsed_mode)
9. Marcar TenantStatus::Active (ou Degraded se passos 4-8 falharem)
10. Retornar JSON { tenant_id, status, baseline_hash, fairness_mode }
```

Falha em qualquer passo → `TenantStatus::Degraded(cause)` + HTTP 502 com
detalhes. Tráfego subsequente para esse tenant cai em fail-soft REDACT.

### D3 — Eager cleanup orquestrado pelo `TenantStorageRouter`

**Correção factual vs plano original:** o orquestrador é o
**`TenantStorageRouter`** (ADR-0083), não `TenantManager` (que não
existe no repo).

`TenantStorageRouter::evict_tenant(tenant_id)` (novo, kernel):

1. Remover entrada do `cache` (`HashMap<String, Arc<DurableLedger>>`).
   Last `Arc` drop libera o `DurableLedger`; arquivos em disco
   permanecem (cleanup de disco é responsabilidade operacional, não
   runtime).
2. Retornar `bool` indicando se a entrada existia.

**Orquestração no gateway** (`AppState::evict_tenant(tenant_id)`):

1. `tenant_router.evict_tenant(tenant_id)`
2. `jonas_monitor.remove_tenant(tenant_id)`
3. `rawls_monitor.remove_tenant(tenant_id)`
4. `fairness_modes` precisa de método `remove(tenant_id)` (entrega do
   Commit 4)
5. `tenant_status_registry.set(tenant_id, removed)` ou `remove()`
6. Métrica `btv_tenant_evictions_total{tenant_id}`

**Por que sem cancelamento de tasks:** D1 do ADR-0088 mantém o cálculo
PSI síncrono inline (sem `tokio::spawn`). Não há tarefas em background
por tenant — o eager cleanup é apenas `HashMap::remove` em cada
estrutura. Quando a última referência `Arc` sair (após qualquer request
em andamento liberar), o tenant é coletado.

**Idempotência:** chamadas repetidas em tenant inexistente são noop em
todos os passos.

### D4 — Benchmark de três cenários via `criterion`

`rust/gateway/benches/fairness_pipeline.rs` mede a P99 de
`compose_fairness_action` + `JonasMonitor::record` em três
configurações:

| Cenário | Setup | Hipótese |
|---|---|---|
| **A. Baseline** | `FairnessMode::Disabled`, sem records | Sem overhead. Estabelece linha de referência. |
| **B. Síncrono N=500** | `Enforced`, baseline instalado; transação N=500 dispara recompute inline (estado atual ADR-0088 D1) | Spike negligível se PSI sub-ms |
| **C. Hipotético spawn_blocking** | Variante experimental que dispara `tokio::task::spawn_blocking` no N=500 | Eventual-consistency + custo de spawn |

**Critério de validação D1 ADR-0088:** se P99(B) ≤ P99(A) + 5ms na carga
de 10k req/s simulada → D1 confirmado, código permanece síncrono. Se
spike > 5ms → ADR-0089 documenta reversão para `spawn_blocking` com
evidência numérica e fica como justificativa para um futuro
ADR-0090 (perf hardening).

Bench config:
```toml
# Cargo.toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "fairness_pipeline"
harness = false
```

---

## Invariantes preservadas

- ADR-0083: `TenantStorageRouter` segue como única factory de ledger.
- ADR-0086 §D2: storage in-memory por tenant; `remove_tenant` é adição.
- ADR-0087 §D2: baseline imutável **durante** runtime entre reloads.
- ADR-0088 §D1: cálculo PSI síncrono inline (validado por D4 deste ADR).
- ADR-0088 §D3: shadow mode preserva semântica monotônica crescente.
- Kernel desconhece filesystem — gateway é quem lê YAML e chama
  `reload_baseline(yaml_content)`.

---

## Entregáveis e ordem de commits

| # | Artefato | Commit |
|---|---|---|
| 1 | Este ADR (status 📋 Proposto) | **deste commit** |
| 2 | `trait ReloadableGuardrail` no kernel + impl em `RawlsMonitor`/`JonasMonitor` + `remove_tenant()` em ambos + `TenantStorageRouter::evict_tenant()` | próximo |
| 3 | `gateway/src/tenant_status.rs` — enums `TenantStatus`/`DegradationCause` + `TenantStatusRegistry` | follow-up |
| 4 | `policy_loader.rs` no gateway — filesystem walk + boot step async + métricas | follow-up |
| 5 | `routes/internal.rs` + `InternalAuthLayer` (constant_time_eq) | follow-up |
| 6 | `AppState::evict_tenant()` orquestrador + `FairnessModeRegistry::remove()` | follow-up |
| 7 | `benches/fairness_pipeline.rs` (criterion, 3 cenários) | follow-up |
| 8 | Testes E2E: boot com YAML ausente/corrompido, reload, evict, benchmark smoke | ADR transita para ✅ Aceito |

---

## Fora desta branch

- E162 (`IntegrityMismatch` + `expected_sha256`) — ADR-0087 Fase 2.
- gRPC `AuditExposer` e ADR-0085 (Java consumer).
- Dashboard de métricas — depende de Grafana setup fora do repo.
- `TenantCacheMoat` — otimização sob evidência (ADR-0090).
- Webhooks reativos (`POST /webhooks/fairness-alert`) — fica para um
  ADR de integração externa.

---

## Referências

- ADR-0082 — API Evolution & Deprecation Policy
- ADR-0083 — Multi-Tenancy Isolation (`TenantStorageRouter`)
- ADR-0086 — Rawls Disparate Impact Monitor
- ADR-0087 — Jonas PSI Engine
- ADR-0088 — Gatekeeper Pipeline Wiring (D1 síncrono preservado, validado por D4 aqui)
- RFC 8941 — Structured Field Values for HTTP (futuro: `Sunset`)
