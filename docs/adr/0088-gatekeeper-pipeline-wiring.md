# ADR-0088: Gatekeeper Pipeline Wiring (Rawls + Jonas Activation)

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta (decisões reconciliadas com revisões consolidadas)
**Impacto**: `rust/gateway/src/routes/decide.rs`, `rust/gateway/src/state.rs`,
             `rust/kernel/src/api/error_as_resource.rs` (ExplainDecision),
             schema YAML do tenant (`policies/{tenant}/*.yaml`), SDK Java
**Pré-requisitos**: ADR-0083 (multi-tenancy), ADR-0086 (Rawls), ADR-0087 (Jonas)

---

## Contexto

ADR-0086 e ADR-0087 mergearam os motores Rawls (DIR) e Jonas (PSI) como
unidades isoladas no kernel. Em produção hoje:

- `compose_fairness_action` existe mas nunca é chamada.
- E160/E161 existem em `EthicalError` mas nunca são emitidos.
- `RawlsMonitor::record` e `JonasMonitor::record` nunca são invocados —
  o `decide_handler` não conhece os monitores.

Este ADR fecha o ciclo: ativa Rawls + Jonas no pipeline de decisão real
da rota `POST /v1/decide`, materializando o valor regulatório dos motores
em respostas HTTP, headers e laudos de explicação.

---

## Decisões (reconciliadas das revisões consolidadas)

### D1 — Cálculo PSI permanece síncrono inline (preserva ADR-0087 §D6)

**Decisão**: manter `JonasMonitor::record` síncrono inline. **Não** introduzir
`tokio::spawn_blocking` nesta fase.

**Justificativa**:
- ADR-0087 §D6 documenta que PSI sobre 10 bins é cálculo sub-milissegundo
  (10 multiplicações + 10 logaritmos). SLA de 50ms p99 não é ameaçado.
- `spawn_blocking` introduz: eventual-consistency entre leitura/escrita,
  risco de pool poisoning (Anexo IV das revisões), necessidade de `Clone`
  do snapshot antes do spawn, e lifecycle complexo de tasks de background
  por tenant.
- Mais simples = menos superfície de bug.

**Critério para reversão** (registra evidência, não preferência):
Reversão para `spawn_blocking` exige ADR de follow-up com benchmark
mostrando que a transação N=500 (a que dispara o recompute) tem
latência acima do p99 das demais. Bench deve usar `criterion` sobre
`compose_fairness_action` + `JonasMonitor::record` em carga sustentada
de 10k req/s por tenant.

### D2 — `governance_errors: Vec<EthicalError>` com `#[serde(default)]` + `legacy_error: Option<EthicalError>`

> **⚠️ v1alpha — schema instável até ADR-0090.** O contrato definido
> nesta seção é classificado **v1alpha** durante a janela de validação
> de performance do pipeline (ADR-0090 + eventual ADR-0091). Campos
> novos podem ser adicionados como `Option<T>` + `#[serde(default)]`
> conforme ADR-0082 (adição não-quebrante). Parceiros Java
> (ADR-0085) integrando antes da estabilização devem prefixar
> consumidores com `v1alpha`. Trânsito para `v1` estável ocorre após
> decisão binária do D1 do ADR-0090.

**Decisão**: estender `ExplainDecision` com dois campos coexistentes:

```rust
#[derive(Serialize, Deserialize)]
pub struct ExplainDecision {
    // ...campos existentes...

    /// Erro singular legado — populado com o primeiro erro detectado
    /// (precedência: Block > Redact > Warning). Preserva FFI Java do
    /// SDK 1.x até migração para 2.x.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_error: Option<EthicalError>,

    /// Vetor completo de erros de governança (Rawls, Jonas, etc).
    /// Default vazio garante backcompat com clientes Jackson que não
    /// conhecem o campo. Adição não-quebrante (ADR-0082).
    #[serde(default)]
    pub governance_errors: Vec<EthicalError>,
}
```

**Justificativa do dual-write**:
- Clientes Java com Jackson configurado `FAIL_ON_UNKNOWN_PROPERTIES=true`
  toleram **adição** de `governance_errors` se eles próprios não o
  declaram (campo desconhecido entra em ignored). Mas tornar o vetor
  **principal** sem preservar `legacy_error` quebra clientes que leem
  o campo singular existente.
- `legacy_error` é populado com `governance_errors[0]` por precedência:
  Block > Redact warning > Warning. Garante que clientes 1.x continuem
  vendo o erro mais importante.
- Migração 1.x → 2.x: clientes leem `governance_errors` quando upgrade
  do SDK Java; até lá `legacy_error` é a fonte de verdade para eles.

### D3 — Shadow mode é **nível de execução**, não feature flag

**Decisão**: `JonasMonitor::record` e `RawlsMonitor::record` ocorrem
**sempre**, em qualquer modo. O modo (shadow vs enforce) afeta apenas
a **aplicação** do `FairnessDecision.action` na resposta HTTP.

```rust
pub enum FairnessExecutionMode {
    /// Calcula tudo, registra evidência, mas mantém ação original.
    /// FairnessDecision.action é registrado em audit_log como
    /// `would_have_been`. Cliente vê a ação tentativa intocada.
    Shadow,
    /// Aplica FairnessDecision.action na resposta HTTP. E160/E161
    /// retornados quando aplicável.
    Enforce,
}
```

**Resolve a "ilusão estatística" do Anexo II das revisões**:
- Buffer de scores Jonas é **sempre populado**, independente do modo.
- Não há feedback negativo no shadow porque a ação tentativa segue —
  isso é **intencional**: shadow mede o que aconteceria se o motor
  estivesse ativo, contra a realidade sem motor.
- Métricas em shadow são monotônicas crescentes por design, **não**
  bug. DPO usa shadow para calibrar threshold + baseline antes de
  enforce; não para validar comportamento estacionário.

**Configuração por tenant** via campo opcional em `policies/{tenant}/fairness.yaml`:

```yaml
mode: shadow  # default | shadow | enforce
```

Ausente → `enforce` para tenants com Jonas baseline registrado;
`shadow` quando baseline está sendo calibrado.

### D4 — Tenant lifecycle: cleanup lazy via TTL

**Decisão**: `JonasMonitor` e `RawlsMonitor` mantêm entradas indefinidamente.
Cleanup é lazy: tarefa periódica (futuro endpoint `/internal/v1/gc`)
varre entradas inativas há mais de `TENANT_IDLE_TTL = 24h` e remove.
Cleanup eager (ao remover tenant do `TenantStorageRouter`) fica para
ADR-0089 (Fairness Observability Loop).

**Justificativa**:
- Tenants removidos são raros em produção (suspensão regulatória,
  off-boarding). Não justifica complexidade de notificação cross-monitor.
- 24h cobre a janela típica de auditoria pós-suspensão (DPO pode
  consultar métricas finais).
- Sem `spawn_blocking` (D1), não há tasks de background por tenant
  para cancelar. Cleanup é apenas remover entrada do `HashMap`.

---

## Sequência de execução (decide_handler pós-wiring)

```
1. Extract Extension<TenantId> (já existe — ADR-0084)
2. Derive TEK (já existe — ADR-0083)
3. Scan evidence via Gatekeeper (síncrono, Mutex<Gatekeeper>)
4. Resolve tentative_action via PolicyEngine (já existe)
5. *** NOVO *** Rawls record + metrics:
   state.rawls_monitor.record(tenant_id, group, outcome);
   let rawls = state.rawls_monitor.metrics_or_disabled(tenant_id);
6. *** NOVO *** Jonas record + metrics:
   state.jonas_monitor.record(tenant_id, score, score_unavailable);
   let jonas = state.jonas_monitor.metrics_or_disabled(tenant_id);
7. *** NOVO *** compose_fairness_action:
   let fairness = compose_fairness_action(tentative, &rawls, jonas.alert);
8. *** NOVO *** Resolve mode via state.fairness_mode(tenant_id):
   let applied_action = if mode == Shadow { tentative } else { fairness.action };
9. *** NOVO *** Build governance_errors:
   - if fairness.rawls_violation: push EthicalError::rawls_dir_violation(...)
   - if fairness.jonas_critical: push EthicalError::jonas_drift_violation(...)
   - legacy_error = governance_errors.first().cloned() (precedência)
10. Persist LedgerEntry + JSONL com applied_action + governance_errors
11. HTTP response com X-BTV-* headers + ExplainDecision atualizado
```

**Falha de monitor (D4 das revisões)**: `metrics_or_disabled` já
retorna `Disabled`/`disabled()` em vez de erro — fail-soft é embutido
no contrato existente. Não precisa de `Result` no pipeline.

---

## Entregáveis e ordem de commits

| # | Artefato | Commit |
|---|---|---|
| 1 | Este ADR + nota em ADR-0087 §D6 confirmando síncrono | **deste commit** |
| 2 | `ExplainDecision` estendido com `legacy_error` + `governance_errors`; teste de precedência | próximo |
| 3 | `FairnessMode` enum + `AppState.fairness_mode(tenant)` (default `Enforce` quando Jonas baseline registrado) | follow-up |
| 4 | `AppState` ganha `Arc<RawlsMonitor>` + `Arc<JonasMonitor>` (já há `rawls_monitor` no Rawls? confirmar) | follow-up |
| 5 | Wire em `decide_handler`: passos 5-10 da sequência acima | follow-up |
| 6 | Testes E2E: `axum_test` cobrindo shadow vs enforce + combo BLOCK + fail-soft em monitor sem baseline | follow-up |

---

## Invariantes preservadas de ADRs anteriores

- ADR-0082: trait `EthicsValidator` síncrono — esta wiring **não usa**
  o trait (Rawls/Jonas têm contexto de tenant que o trait não carrega).
  Composição é via função pura `compose_fairness_action`, sem registry.
- ADR-0083: `TenantStorageRouter` segue como única factory de ledger.
  `AppState.rawls_monitor`/`jonas_monitor` são **independentes** dele.
- ADR-0086 §D2: storage in-memory por tenant preservado, sem refactor.
- ADR-0087 §D2: baseline YAML carregado uma vez no boot; reload é
  endpoint futuro.
- ADR-0087 §D6: síncrono inline confirmado por D1 deste ADR.

## Out-of-scope (ADRs futuros)

- ADR-0085 — Java `ResilientAuditStreamConsumer` (depende do schema
  `FairnessDecision` que este ADR materializa em `governance_errors`).
- ADR-0089 — Fairness Observability Loop (dashboard, webhooks, cleanup
  eager por tenant lifecycle, benchmarks para reversão de D1).
- E162 — `IntegrityMismatch` em `JonasBaselineLoader` com
  `expected_sha256` (audit-only hoje, ADR-0087 Fase 2).

---

## Referências

- ADR-0082 — API Evolution & Deprecation Policy
- ADR-0083 — Multi-Tenancy Isolation
- ADR-0086 — Rawls Disparate Impact Monitor
- ADR-0087 — Jonas PSI Engine
- ADR-0011 — Policy Engine (predecessor do pipeline declarativo)
