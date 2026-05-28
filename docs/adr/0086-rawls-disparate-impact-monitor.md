# ADR-0086: Rawls Disparate Impact Monitor (DIR Engine)

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta (validado por revisões consolidadas)
**Impacto**: `rust/kernel/src/statistics/`, `rust/kernel/src/gatekeeper.rs`,
             `rust/kernel/src/api/error_as_resource.rs`,
             `docs/api-reference.md`, ADR-0010 (BiasDeclaration)
**Slot reservado**: ADR-0085 (Java ResilientAuditStreamConsumer)
**Acompanhamento**: ADR-0087 (Jonas PSI Engine — separado por requerer
                    gestão de baseline histórico ortogonal ao DIR).

---

## Contexto

O princípio rawlsiano de justiça como equidade exige que decisões
algorítmicas não produzam impacto desproporcional sobre grupos
vulneráveis. A métrica regulatória aceita pela LGPD Art. 20, EU AI Act
Art. 14 e EEOC 80% Rule é o **Disparate Impact Ratio (DIR)**:

```
DIR = P(outcome_favorável | grupo_desprivilegiado)
      ────────────────────────────────────────────
      P(outcome_favorável | grupo_privilegiado)
```

Convenção legal: DIR < 0.80 caracteriza disparate impact (regra dos 4/5).

Hoje o BTV não monitora DIR em runtime. Decisões `ALLOW`/`REDACT`/`BLOCK`
são tomadas e auditadas, mas não há sinal automático quando a distribuição
de outcomes diverge entre grupos protegidos. ADR-0086 introduz o
**Rawls DIR Engine** como `EthicsValidator` plugável (contrato ADR-0082).

---

## Decisões

### D1 — Fonte do `group_classification`: `AttestedContext` explícito

O grupo é declarado pelo chamador via campo dedicado em
`AttestedContext.group_classification: Option<GroupClass>`, validado
contra a política YAML do tenant. **Nunca inferido** de outros campos
(idade, CPF, IP, profile) — evita pseudo-anonimização reversa e mantém
explicabilidade.

`GroupClass` é um enum fechado:
- `Privileged` — referência da política do tenant
- `Unprivileged` — grupo monitorado para fairness
- `Unclassified` — request fora da janela amostral (não conta no DIR)

JWT autentica tenant; AttestedContext carrega o dado de negócio.

### D2 — Storage: ring buffer in-memory por tenant (não SQL)

**Crítico — divergência de premissas em revisões anteriores:**
o ledger BTV é arquivo binário (`LedgerEntry` de 384 bytes) + WAL,
**não SQLite**. Não há tabela onde criar índice composto.

Decisão para v1:
- **`RawlsCounters` por tenant**: ring buffer de tamanho fixo
  (`RAWLS_WINDOW_SIZE = 10_000` eventos) com contadores agregados por
  `(GroupClass, OutcomeBucket)`.
- **Atualização**: o Gatekeeper, após cada decisão, chama
  `RawlsMonitor::record(tenant_id, group, outcome)`. O monitor mantém
  um `HashMap<tenant_id, RawlsCounters>` protegido por `RwLock`.
- **Cálculo**: `compute_dir()` é O(1) pois os contadores já estão
  agregados — não há scan de eventos.
- **Persistência**: ortogonal — snapshots periódicos para o ledger
  ficam em ADR futuro (Fase 2). v1 é volátil; aceito para validação
  do motor antes de produção.

A alternativa de adicionar SQLite ao ledger é deliberadamente
**fora de escopo** — exige ADR separado (multi-tenancy storage v2).

### D3 — Outcome favorável: `ALLOW ∪ REDACT`

```
favorable(action) := match action {
    Action::Allow => true,
    Action::Redact => true,   // PII mascarada mas requisição prosseguiu
    Action::Log    => true,   // EDUCATE: usuário recebeu resposta
    Action::Block  => false,
}
```

Convenção documentada para evitar ambiguidade na implementação e nos
testes. Alinhado com a doutrina de "misericórdia procedimental" do
Gilligan Mercy Algorithm (ADR-0072).

### D4 — Threshold: const compilado, override YAML em Fase 2

```rust
pub const DEFAULT_DIR_THRESHOLD: f64 = 0.80;
pub const RAWLS_WINDOW_SIZE: usize = 10_000;
pub const RAWLS_MIN_SAMPLES_PER_GROUP: u64 = 30; // statistical floor
```

Compilados no kernel como fallback seguro. Override por tenant via
`policies/{tenant}/rawls.yaml` é adição não-quebrante (Fase 2 do
mesmo ADR — `Option<f64>` no parser de política).

Abaixo do threshold mínimo de amostras (`< 30` em qualquer grupo), o
engine retorna `EthicsDecision::Allow` com flag `insufficient_samples`
— evita falsos positivos por amostra pequena.

### D5 — Erro E160 (Anomalia de Equidade) com Fail-Closed

Quando `DIR < threshold` e o motor é configurado em modo `enforce`:
- Action original `Allow` → rebaixada para `Redact` (degradação suave)
- Action original `Redact`/`Log` → mantida (já é fail-safe)
- Plugin retorna `EthicsDecision::Block { reason: "rawls_dir_below_threshold", adr_ref: "0086-rawls-disparate-impact-monitor" }` apenas em modo `hard_enforce`

Em modo `monitor` (default em produção inicial), apenas registra
violação em `ExplainDecision.rawls_rationale` sem bloquear — permite
calibração do threshold antes de enforce.

Novo erro RFC 7807:

```
E160 — https://docs.buildtovalue.org/errors/E160
title: "Anomalia de Equidade — DIR abaixo do threshold"
status: 451 (Unavailable For Legal Reasons)
ethical_ground: "Distribuição de outcomes viola regra dos 4/5 (DIR < 0.80)"
contestable: true (24h)
```

---

## Entregáveis (ordem de commit nesta branch)

1. **Commit 1** (✅ feito em `80f7884`): fix de regressão CI no `BtvClaims`.
2. **Commit 2** — ADR-0086 (este documento) + `rust/kernel/src/statistics/rawls.rs` com:
   - `GroupClass`, `OutcomeBucket`, `RawlsCounters`, `FairnessMetrics`
   - `RawlsMonitor` (HashMap tenant → counters, RwLock)
   - Função `compute_dir(counters: &RawlsCounters) -> FairnessMetrics`
   - Testes com dados sintéticos: paridade, disparate impact 4/5,
     insufficient samples, threshold boundary.
3. **Commit 3** — `EthicsValidator` impl + erro E160 em `error_as_resource.rs`.
4. **Commit 4** — Integração no Gatekeeper: hook pós-decisão para
   `RawlsMonitor::record`; flag `enforce_mode` na política.

**Fora desta branch:**
- Override YAML por tenant (Fase 2, ADR-0086 §D4).
- Persistência de snapshot no ledger (ADR futuro).
- ExplainDecision.stages.rawls estruturado (depende de refactor da
  struct ExplainDecision, Fase 3 do roadmap).

---

## Invariantes

1. `GroupClass::Unclassified` **nunca** entra no cálculo de DIR.
2. `compute_dir` retorna `FairnessMetrics { dir: f64::NAN, ... }` quando
   `samples(Privileged) < MIN_SAMPLES` OU `samples(Unprivileged) < MIN_SAMPLES`.
3. Ring buffer overflow: políticas de eviction FIFO; `RawlsMonitor` nunca
   bloqueia o hot path por falta de espaço.
4. Sem `panic!`/`unwrap` no caminho de runtime — testes podem usar.

---

## Referências

- ADR-0010 — BiasDeclaration Mandate
- ADR-0017 — Contestability Loop (SLA 24h)
- ADR-0072 — Gilligan SLA Mercy Algorithm
- ADR-0082 — API Evolution & Deprecation Policy (`EthicsValidator` contract)
- ADR-0083 — Multi-Tenancy Isolation (TenantStorageRouter)
- LGPD Art. 20 (decisões automatizadas)
- EU AI Act Art. 14 (oversight humano)
- EEOC 80% Rule (Uniform Guidelines on Employee Selection Procedures, 1978)
- Rawls, J. (1971) — *A Theory of Justice*
