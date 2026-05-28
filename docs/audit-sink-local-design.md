# `audit-sink-local` — Local Audit Sink Design

**Status**: 📋 Design (não-ADR — implementa decisões já tomadas)
**Data**: 28 de maio de 2026
**Pré-requisitos**: ADR-0083, ADR-0086, ADR-0087, ADR-0088 (schema
                    v1alpha §D2), ADR-0089, ADR-0090
**Sucessor**: gRPC `AuditExposer` (sprint paralela)

---

## Por que este documento não é um ADR

Não introduz decisão arquitetural nova. Implementa o que ADR-0088 e
ADR-0090 deixaram pendente: um sink local para `FairnessAuditEvent`
que destrava observabilidade mínima **antes** do gRPC `AuditExposer`.

ADR-0088 §D2 marcou o schema `FairnessDecision` como `v1alpha`;
ADR-0090 confirmou a viabilidade do pipeline síncrono. Sem um sink
consumindo, os eventos seriam emitidos para o vazio — Anexo II das
revisões do ADR-0088 sinalizou esse risco.

Este doc serve como referência operacional para SRE/DPO que vão
consumir os eventos (JSONL particionado por tenant). Quando o gRPC
`AuditExposer` chegar, o sink local **continua** como fallback de
proteção contra perda de auditoria.

---

## Decisões consolidadas

### D1 — `FairnessAuditEvent` em `gateway/src/audit/event.rs`

Schema é apresentação HTTP-layer. Kernel permanece storage-agnóstico
(`LedgerEntry` binário já é o registro forense canônico). O
`FairnessAuditEvent` é a projeção humano-legível.

Campos:

```rust
pub struct FairnessAuditEvent {
    pub schema_version: &'static str,  // "v1alpha"
    pub event_id: String,              // UUID v7
    pub ts_unix_ms: u128,
    pub tenant_id: String,
    pub verdict_id: String,

    pub fairness_mode: FairnessMode,
    pub tenant_status: TenantStatus,
    pub tentative_action: String,
    pub applied_action: String,
    pub composed_action: String,

    pub composition_changed_action: bool,
    pub apply_override: bool,
    pub rawls_violation: bool,
    pub jonas_critical: bool,
    pub jonas_warning: bool,
    pub hard_block: bool,
    pub human_review_required: bool,

    pub governance_error_codes: Vec<&'static str>,
    pub legacy_error_code: Option<&'static str>,
}
```

### D2 — `AuditSink` trait + 4 implementações

```rust
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: FairnessAuditEvent);
}
```

- `JsonlAuditSink` — `{BTV_AUDIT_DIR}/{tenant_id}/events.jsonl`,
  append-only, append-best-effort.
- `StdoutAuditSink` — `tracing::info!` estruturado.
- `MultiAuditSink(Vec<Arc<dyn AuditSink>>)` — fan-out (tee).
- `NullAuditSink` — para tests e tenants opt-out (futuro).

`GrpcAuditSink` adicionado ao `MultiAuditSink` quando gRPC existir —
zero refactor do pipeline.

### D3 — Backpressure: bounded mpsc + drop com métrica

`tokio::sync::mpsc::channel::<FairnessAuditEvent>(10_000)`. Hot path
faz `try_send` (não bloqueia). Falha → `btv_audit_events_dropped_total
{reason}` incrementa.

**Justificativa:** ADR-0088 §D1 manteve hot path síncrono. Bloquear no
canal re-introduz async pela porta dos fundos. Auditoria perdida sob
load extremo é preferível a violar SLA do Core Banking — e a métrica
dá sinal operacional para investigar.

### D4 — Drainer simples (loop explícito, sem respawn)

```rust
tokio::spawn(async move {
    loop {
        match rx.recv().await {
            Some(event) => sink.emit(event),
            None => break, // canal fechado = shutdown gracioso
        }
    }
});
```

`tokio::spawn` aqui é em **boot time**, não no hot path — não viola
ADR-0088 §D1.

**Limitação conhecida:** panic dentro de `sink.emit()` derruba a task
sem respawn automático. Mitigação: `std::panic::catch_unwind` em volta
de cada `emit` log error + métrica `btv_audit_drainer_panics_total`,
sem spawn nova task (evita loop infinito se o sink estiver
permanentemente quebrado por bug). Operador alerta + redeploy.

### D5 — Persistência

`{BTV_AUDIT_DIR}/{tenant_id}/events.jsonl`. Default:
- Dev: `./data/audit`
- Prod: `/var/log/btv/audit`

Configurável via env `BTV_AUDIT_DIR`. Append-only. Rotação de arquivo
é responsabilidade de ops (logrotate/journald) — **out-of-scope**
desta sprint.

Distinto de `data/ledger/{tenant_id}/decisions.jsonl` (ADR-0083 — ledger
forense, kernel-side, hash-chained). `audit/` é o sink humano-legível
para SIEM/SecOps/DPO.

### D6 — `schema_version: "v1alpha"`

Em todo evento. Consumidores filtram por versão. Adições via
`#[serde(default)]` (ADR-0082). Trânsito para `v1` quando gRPC
`AuditExposer` estabilizar o schema (pós-validação operacional).

### D7 — Filtro por tenant (NÃO nesta sprint)

Trait aceita futuro `should_emit(tenant_id) -> bool` para opt-out.
Por agora, **todo tenant com `mode != Disabled` emite**.

### D8 — Localização confirmada: gateway

`gateway/src/audit/event.rs` para o struct + `gateway/src/audit_sink.rs`
para implementações + `gateway/src/audit_drainer.rs` para o canal.

Kernel não conhece o schema HTTP/JSONL. Schema é apresentação;
múltiplos gateways podem ter projeções diferentes do mesmo
`LedgerEntry` binário.

---

## Riscos e mitigações

| Risco | Mitigação |
|---|---|
| `try_send` falha sob load — auditoria perdida | Métrica Prometheus `btv_audit_events_dropped_total{reason}` |
| Drainer task crash via panic em sink | `catch_unwind` + métrica + log error; **sem respawn** (evita loop infinito) |
| Disco cheio → escrita JSONL falha | Sink loga `tracing::error!` + métrica; drainer continua best-effort |
| JSONL filesize cresce indefinidamente | Out-of-scope: ops gerencia via logrotate |
| Schema v1alpha muda — quebra consumidor existente | `schema_version` em todo evento; consumidores devem checar |

---

## Aceitação

- [ ] `FairnessAuditEvent` v1alpha serializa/deserializa corretamente
- [ ] `JsonlAuditSink` escreve em path tenant-particionado
- [ ] `StdoutAuditSink` emite via tracing estruturado
- [ ] `MultiAuditSink` fan-out funciona
- [ ] Drainer task vive em background + drena canal
- [ ] `try_send` falha → métrica incrementa
- [ ] Panic no sink → catch_unwind + log + métrica, task continua
- [ ] E2E: requisição decide → JSONL escrito com event_id + verdict_id
- [ ] E2E: 10k requests → drops contados, sem panic no handler
- [ ] Bench: latência de `try_send` < 1 µs
- [ ] Strict clippy verde

---

## Operação (referência SRE/DPO)

### Localizar eventos de um tenant

```bash
tail -f /var/log/btv/audit/{tenant_id}/events.jsonl | jq .
```

### Filtrar por flag

```bash
jq 'select(.hard_block == true)' /var/log/btv/audit/*/events.jsonl
```

### Verificar drops

```
btv_audit_events_dropped_total
btv_audit_drainer_panics_total
```

Ambas devem ficar próximas a zero em operação normal. Crescimento
súbito = investigar load ou bug no sink.

---

## Próximos passos

Após esta sprint:
1. gRPC `AuditExposer` consome o mesmo `FairnessAuditEvent` v1alpha
   sobre o wire (Tonic). Sink local continua escrevendo localmente
   para fallback.
2. Java `ResilientAuditStreamConsumer` (ADR-0085) consome do gRPC.
3. Estabilização do schema → v1.
