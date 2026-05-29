# ADR-0091: gRPC Audit Exposer

**Status**: ✅ ACEITO (implementado)
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `rust/gateway/` — novo módulo `audit/grpc_exposer.rs`,
             `proto/audit_exposer.proto`, `build.rs`, segundo listener em
             `main.rs`. Reuso de `audit/event.rs` (schema) e
             `middleware/internal_auth.rs` (auth).
**Pré-requisitos**: sprint `audit-sink-local` (PR #172 + commit 5 do wire) em
             main — `FairnessAuditEvent` v1alpha + `JsonlAuditSink`.

---

## Contexto

A sprint `audit-sink-local` deixou o gateway persistindo cada decisão de
fairness como `FairnessAuditEvent` v1alpha em JSONL particionado por tenant
(`{audit_dir}/{tenant}/events.jsonl`). Falta o transporte sobre o wire: o
roadmap prevê um `ResilientAuditStreamConsumer` em Java (ADR-0092) que
consome esse fluxo para dashboards, alertas e análise de viés fora do
processo do gateway.

ADR-0091 entrega o **produtor**: um servidor gRPC (Tonic) que faz *streaming*
dos eventos de auditoria. O Java (e qualquer outro consumidor) depende
**apenas** do contrato `.proto` — não do crate Rust.

---

## Decisões

### D1 — Co-location no `btv-gateway` (não um crate separado)

O servidor gRPC é um **módulo dentro de `btv-gateway`**
(`audit/grpc_exposer.rs`), erguido como segundo listener (porta `GRPC_PORT`,
default `9090`) em paralelo ao HTTP no `main.rs`.

**Justificativa (YAGNI):** reusa `FairnessAuditEvent` (schema), o segredo
`BTV_INTERNAL_SECRET` e o `audit_dir` sem duplicar struct nem plumbing. Um
crate separado exigiria mover `FairnessAuditEvent` para um crate de tipos
compartilhado (ou duplicá-lo) e replicar a auth — custo sem benefício atual.
O isolamento de processo (Opção 2) só se justifica sob evidência de gargalo;
o `.proto` já desacopla o consumidor Java do binário Rust.

### D2 — Fonte = tail dos JSONL existentes (read-only)

O exposer **taila os arquivos JSONL** que o `JsonlAuditSink` já escreve, em
**modo leitura**. Não há um `GrpcAuditSink` novo no `MultiAuditSink`.

**Consequência crítica:** o tailer abre o arquivo do disco independentemente;
**jamais adquire o `Mutex` de escrita do `JsonlAuditSink`** → sem contenção
(*starvation*) no hot path de decisão. O JSONL local continua sendo o buffer
durável e o fallback.

### D3 — Polling 100ms (sem `notify`)

O tail é por **polling** (`tokio::time::interval(100ms)`) com tracking de
byte-offset por arquivo. Rejeitamos `notify` (inotify/kqueue): adiciona dep e
complexidade de portabilidade para latência que um audit stream não exige.

O offset avança **somente até o último `\n`**; uma linha parcial (leitura no
meio de uma escrita) é re-lida no tick seguinte — sem buffer de resíduo.

### D4 — RPC único com filtro opcional por tenant

```protobuf
service AuditExposer {
  rpc StreamAuditEvents(StreamRequest) returns (stream FairnessDecision);
}
message StreamRequest { string tenant_id = 1; } // vazio = todos os tenants
```

`tenant_id` preenchido ⇒ taila `{audit_dir}/{tenant}/events.jsonl`; vazio ⇒
varre os subdirs de `audit_dir` a cada tick (descobre tenants novos). Um único
endpoint cobre o consumidor individual e a observabilidade global.

### D5 — Backpressure por `send().await` (sem drop)

Cada conexão tem um canal `mpsc` bounded (1024). O tailer usa `send().await`:
se o consumidor está lento, o tailer **atrasa a leitura** em vez de dropar —
o dado é durável no JSONL, então não há perda. Isto é o **oposto** da decisão
do drainer in-memory (commit 5), onde dropar com métrica era correto porque a
fonte era um canal volátil.

### D6 — Auth reusando `internal_auth` (ADR-0089 §D2)

Interceptor Tonic valida o metadata `x-btv-internal-key` contra
`BTV_INTERNAL_SECRET` (≥32 bytes) em **tempo constante** (`subtle::ConstantTimeEq`).
A lógica é extraída em helpers `pub(crate)` (`internal_secret_from_env`,
`check_internal_key`) reusados pelo layer HTTP **e** pelo interceptor gRPC —
fonte única, sem duplicação. Chave errada ⇒ `Status::unauthenticated`; chave
ausente/curta ⇒ `Status::unavailable` (fail-secure).

### D7 — protoc vendorizado (CI sem instalação)

`crate_release_audit.yml` roda `cargo clippy --workspace --all-targets`
(que executa todos os `build.rs`) e **não instala `protoc`**. O `build.rs`
usa `protoc-bin-vendored` para fornecer o compilador — sem editar workflows,
sem dependência de sistema. O código gerado por `tonic`/`prost` é isolado num
módulo `pb` com `#![allow(clippy::all, clippy::clone_on_ref_ptr, …)]` (os
lints de restrição do CI não são cobertos por `clippy::all`).

### D8 — Versionamento do contrato de wire

O `.proto` é o contrato. Os enums Rust (`FairnessMode`, `TenantStatus`) são
**achatados para string** (ex: `"shadow"`, `"active"`) para estabilidade.
`ts_unix_ms` (`u128` no Rust) vira `uint64` saturado. Mudança de semântica de
campo existente = breaking (major do contrato); adição de campo com tag nova =
não-quebrante. `schema_version` ("v1alpha") viaja no payload.

---

## Implementação

- `proto/audit_exposer.proto` — `package btv.audit.v1alpha`, `FairnessDecision`
  espelhando `FairnessAuditEvent`.
- `build.rs` — `protoc-bin-vendored` + `tonic_build::compile_protos`.
- `audit/grpc_exposer.rs` — `GrpcAuditExposer` (impl do serviço), tailer
  poll-based com offset, `event_to_proto`, `AuthInterceptor`, `serve_grpc` +
  `serve_grpc_with_listener`, métrica `btv_grpc_audit_streamed_total{tenant}`.
- `main.rs` — `tokio::try_join!` de HTTP (Axum) + gRPC (Tonic).
- `middleware/internal_auth.rs` — helpers compartilhados extraídos.
- Deps: `tonic = "0.12"`, `prost = "0.13"`, `tokio-stream`, build-deps
  `tonic-build = "0.12"` + `protoc-bin-vendored = "3"`.

## Testes

- `audit/grpc_exposer.rs` (lib): `event_to_proto_is_faithful` (contrato 1:1),
  `read_new_events_tails_complete_lines_only` (offset/linha parcial).
- `tests/grpc_exposer_tests.rs` (E2E): stream entrega o evento tailado com
  chave válida; `wrong_key`/`missing_key` ⇒ `Unauthenticated`.

Verificado: `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --
-D clippy::unwrap_used -D clippy::expect_used -D clippy::clone_on_ref_ptr` →
ok. 416 kernel + 93 gateway lib + 31 integração verdes.

---

## Notas

- A reserva condicional de perf hardening (antes rotulada "ADR-0091" no
  handoff) permanece **sem número fixo** até ser agendada — só dispara se o
  hardware de produção regredir > 5 ms (critério do ADR-0090).
- **Próximo:** ADR-0092 — `ResilientAuditStreamConsumer` (Java) consumindo
  `StreamAuditEvents` com reconexão e cursor por `event_id` (UUID v7 ordenável).
- **Futuro:** drain-on-SIGTERM (flush) e estabilização do schema → `v1`.
