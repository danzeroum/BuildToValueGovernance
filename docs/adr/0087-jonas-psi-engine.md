# ADR-0087: Jonas PSI Engine (Population Stability Drift Monitor)

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta (validado por três rodadas de revisão)
**Impacto**: `rust/kernel/src/statistics/`, `rust/kernel/src/gatekeeper.rs`,
             `rust/kernel/src/api/error_as_resource.rs`,
             `policies/{tenant_id}/drift_baseline.yaml`
**Acompanhamento**: ADR-0086 (Rawls DIR — equidade demográfica)

---

## Contexto

Onde **Rawls** mede equidade entre grupos *demográficos* em um instante,
**Jonas** mede a estabilidade da distribuição *populacional* ao longo do
tempo — detectando *data drift* que pode invalidar a calibração do modelo.

A métrica regulatória aceita é o **Population Stability Index (PSI)**:

```
PSI = Σ_i (A_i - R_i) · ln(A_i / R_i)

  A_i = proporção observada no bin i (janela atual)
  R_i = proporção de referência no bin i (baseline aprovado pelo DPO)
```

Convenção:
- `PSI < 0.10` → distribuição estável (nominal)
- `0.10 ≤ PSI < 0.25` → drift moderado (warning)
- `PSI ≥ 0.25` → drift crítico (action required)

A separação de Rawls e Jonas é deliberada: Jonas exige **gestão de baseline
histórico** (versionamento, aprovação DPO, expurgo) que é ortogonal ao
cálculo instantâneo do DIR. Tratá-los no mesmo ADR violaria coesão.

---

## Decisões

### D1 — Fonte do score: `decision_confidence` em `AttestedContext`

```rust
pub struct AttestedContext {
    // ...campos existentes
    pub decision_confidence: Option<f64>, // 0.0..=1.0
}
```

Campo opcional. Se ausente:
- Motor opera com valor `0.5` e flag `score_unavailable: true` na
  `DriftMetrics`.
- Log de aviso (`tracing::warn!`) com `tenant_id`.
- Flag propagada a `ExplainDecision.stages.jonas.signals.score_quality`
  para que operadores humanos vejam que a análise usou score artificial.

Nunca infere score de outros campos — mesmo princípio do D1 do ADR-0086.

### D2 — Baseline obrigatório via YAML, sem fallback observado

```yaml
# policies/{tenant_id}/drift_baseline.yaml
version: "1.0.0"
model_id: "creditscore-v3.2.1"
bins: 10
reference_proportions:
  - 0.05  # bin [0.0, 0.1)
  - 0.07  # bin [0.1, 0.2)
  - 0.10
  - 0.13
  - 0.15
  - 0.18
  - 0.15
  - 0.10
  - 0.05
  - 0.02
# soma DEVE ser 1.0 ± 1e-6
```

`JonasBaselineLoader` valida:
1. `count(reference_proportions) == bins`
2. `|sum(reference_proportions) - 1.0| < 1e-6`
3. Todos os valores em `[0.0, 1.0]`
4. Hash SHA-256 do conteúdo (excluindo comentários) computado e armazenado
   como `baseline_hash` — emitido em `ExplainDecision.stages.jonas.baseline_hash`
   para que mudanças assinadas pelo DPO sejam rastreáveis na cadeia de auditoria.

**Limitação de Fase 1 (audit-only):** o `baseline_hash` é computado e
propagado, mas o loader **não verifica** contra um `expected_sha256` em
configuração externa. Tampering silencioso do YAML produz um novo hash
mas não bloqueia o carregamento. Reservado para Fase 2 (hardening):
- Novo campo `expected_sha256` em `policies/{tenant}/drift_baseline.yaml`
  ou em `tenant_config.yaml` separado, assinado fora-de-banda.
- Mismatch → `BaselineError::IntegrityMismatch` + erro RFC 7807 **E162**
  reservado.
- Verificação ativa transforma o hash de evidência forense passiva em
  fronteira de admissão.

Operadores que dependem de integridade ativa hoje devem validar o YAML
antes do deploy (CI/CD com `sha256sum` versus referência aprovada).

**Sem fallback para janela observada.** YAML ausente ou inválido →
Jonas desativado para o tenant (`tracing::error!` + `DriftAlert::Disabled`).
Filosofia Jonas: baseline sem aprovação humana viola responsabilidade
sobre o modelo. Outros estágios (Rawls, etc.) continuam funcionando.

### D3 — Regularização de Laplace com `ε = 1e-9` + normalização pós-suavização

```rust
const EPSILON: f64 = 1e-9;

fn smooth_and_normalize(counts: &[f64]) -> Vec<f64> {
    let n = counts.len() as f64;
    let sum: f64 = counts.iter().sum();
    let smoothed: Vec<f64> = counts.iter()
        .map(|&c| (c + EPSILON) / (sum + EPSILON * n))
        .collect();
    // Normaliza para garantir sum ≈ 1.0 mesmo com erros de ponto flutuante.
    let smoothed_sum: f64 = smoothed.iter().sum();
    smoothed.iter().map(|&x| x / smoothed_sum).collect()
}
```

`ε = 1e-9` (não 1e-5) — para distribuições com muitos bins, denominadores
maiores reduzem o viés introduzido pela suavização. Normalização pós-suavização
elimina drift numérico em PSIs próximos do zero.

### D4 — Limiares, consequências e composição com Rawls

| PSI | Status | Ação no `EthicsDecision` | Erro RFC 7807 |
|---|---|---|---|
| `< 0.10` | Nominal | sem interferência | — |
| `[0.10, 0.25)` | Warning | `Allow` mantido, flag no laudo | — |
| `≥ 0.25` | Critical | `Allow` → `Redact`, `human_review_required: true` | **E161** (HTTP 451) |
| Critical + Rawls Critical simultâneos | Crisis | `Block` (Hard Block) | **E160 + E161** combinados |

`E161 — https://docs.buildtovalue.org/errors/E161`
- title: "Anomalia de Drift Populacional — PSI acima do threshold"
- status: 451 (Unavailable For Legal Reasons)
- ethical_ground: "Distribuição observada diverge significativamente do baseline aprovado"
- contestable: true (24h)

Hard Block reservado para composição **Rawls Critical AND Jonas Critical** —
evidência simultânea de desvio demográfico e populacional sinaliza falha
sistêmica do modelo, não caso isolado.

### D5 — Estado por tenant em estrutura paralela ao Rawls

`JonasMonitor` mantém `RwLock<HashMap<String, TenantJonasState>>` —
estrutura **paralela** ao `RawlsMonitor`, não compartilhada. Justificativa:

- `RawlsCounters` (já mergeado em ADR-0086) só armazena agregados u64
  e não carrega `Mutex`/`AtomicU64`. Mesclá-los no mesmo HashMap exigiria
  refactor da implementação Rawls já em produção, o que não justifica
  o ganho.
- A contenção que os reviewers temiam vem de ter um único `RwLock`
  global cobrindo dois domínios distintos. Manter monitores separados
  com locks independentes preserva o mesmo benefício de granularidade
  por tenant — múltiplos tenants podem escrever no Jonas sem bloquear
  o Rawls e vice-versa.

```rust
pub struct TenantJonasState {
    /// Scores recentes; FIFO 10k (D6). Mutex granular por tenant.
    buffer: Mutex<VecDeque<f64>>,
    /// Transações desde o último compute_psi (D6).
    tx_since_compute: AtomicU64,
    /// Última métrica calculada — eventual consistency permitida.
    last_metrics: Mutex<Option<DriftMetrics>>,
    /// Baseline imutável (Arc para clone barato; carregado no boot).
    baseline: Arc<JonasBaseline>,
}
```

`TenantJonasState` deliberadamente **não deriva `Clone`** — `Mutex` e
`AtomicU64` impossibilitam clonagem segura. Acesso é sempre via
referência através do `RwLock` do `HashMap`.

Mesclagem opcional em um `TenantCacheBlock` único pode ser feita em
ADR futuro quando houver evidência de overhead mensurável (>1% no
SLA p99). Até lá, separação é mais simples e equivalente em performance.

### D6 — Cálculo síncrono a cada 500 transações no buffer

Contador atômico por tenant (`tx_since_last_compute`). Quando atinge
`JONAS_COMPUTE_INTERVAL = 500`, chamada síncrona a `compute_psi()`
acontece no caminho do handler.

**Justificativa para síncrono:** PSI sobre ≤ 100 bins é cálculo
sub-milissegundo (10 multiplicações + 10 logaritmos). `tokio::spawn`
introduziria complexidade de eventual-consistency sem benefício
mensurável no SLA de < 50ms. Caminho rápido (sem cálculo) é 1 leitura
atômica + 1 comparação — irrelevante para latência.

**Salvaguarda de warm-up (Anexo I/§2 dos reviewers):**
Se `buffer.len() < JONAS_MIN_SAMPLES = 500`, status é `DriftAlert::WarmUp`
— PSI calculado mas sinalizado como insuficiente para acionar E161.
Evita falsos positivos massivos em arranque/restart.

---

## Invariantes

1. **Sem `tokio::spawn` no caminho de cálculo PSI.** Cálculo é síncrono,
   curto, e bloqueia apenas o `Mutex<VecDeque>` do tenant atual.
2. **Baseline imutável durante execução.** Recarga apenas via reinício ou
   endpoint interno `/internal/v1/reload-policy` (commit futuro).
3. **`compute_psi(window, baseline) -> DriftMetrics` é pura** — sem I/O,
   sem mutação, sem dependência de estado global. Testável em unidade.
4. **`Unclassified` em Rawls é ortogonal**: Jonas observa *toda* transação
   (incluindo Unclassified), porque drift populacional inclui mudança na
   proporção de "classificados".
5. Sem `panic!`/`unwrap` no caminho de runtime.

---

## Fluxo de decisão no Gatekeeper (sequência Commit 5)

```
Request
   │
   ▼
[Validation Stage]   ─→ findings, composite_risk
   │
   ▼
[Policy Engine]      ─→ tentative_action (ALLOW|REDACT|BLOCK)
   │
   ▼
[Rawls Stage]        ─→ rawls_metrics. Se Critical: ALLOW → REDACT (D5 ADR-0086).
   │
   ▼
[Jonas Stage]        ─→ jonas_metrics.
   │                     · Warning: flag no laudo
   │                     · Critical: REDACT + human_review_required
   │                     · Critical AND Rawls Critical: BLOCK
   ▼
[ExplainDecision]    ─→ inclui stages.rawls + stages.jonas (com baseline_hash)
   │
   ▼
[LedgerEntry::finalize_with_key(tek)]  → DurableLedger.append
   │
   ▼
HTTP Response (com X-BTV-Decision-Id, X-BTV-Verdict-Signature)
```

---

## Entregáveis e ordem de commits (este branch)

| # | Artefato | Commit |
|---|---|---|
| 1 | Este ADR (status 📋 Proposto) | **deste commit** |
| 2 | `statistics/jonas.rs` — pura: structs + `compute_psi()` + tests | próximo |
| 3 | `JonasBaselineLoader` — parse YAML + validação + hash | follow-up |
| 4 | `JonasMonitor` — buffer por tenant + record/maybe_compute | follow-up |
| 5 | Integração `Gatekeeper` — E161 + composição com Rawls | follow-up |
| 6 | Testes E2E síntéticos: parity, drift severo, partial drift, warm-up, combo Rawls+Jonas → BLOCK | follow-up |

---

## Fora desta branch

- Endpoint `/internal/v1/reload-policy` (recarga dinâmica de baseline).
- `AppealView` enriquecida com PSI e top-contributing bin (Reviewer 2 §10).
- Métricas Prometheus para `btv_jonas_psi_per_tenant`.
- ExplainDecision struct refactor (depende de Fase 3 do roadmap).

---

## Referências

- ADR-0010 — BiasDeclaration Mandate
- ADR-0017 — Contestability Loop (SLA 24h)
- ADR-0082 — API Evolution & Deprecation Policy
- ADR-0083 — Multi-Tenancy Isolation
- ADR-0086 — Rawls Disparate Impact Monitor (compartilha `TenantCacheBlock`)
- Jonas, H. (1979) — *Das Prinzip Verantwortung*
- Sankaran, R. (2014) — "Population Stability Index for Model Monitoring"
- LGPD Art. 20 (decisões automatizadas)
- EU AI Act Art. 9 (risk management for high-risk AI systems)
