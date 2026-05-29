# ADR-0092: Java ResilientAuditStreamConsumer

**Status**: 📋 PROPOSTO (consumer Java em repositório externo)
**Data**: 29 de maio de 2026
**Autores**: IA Arquiteta
**Impacto neste repositório**: `rust/gateway/proto/audit_exposer.proto`
             (campo `resume_after_event_id`) + `audit/grpc_exposer.rs` (skip
             do cursor no tailer). O código Java vive em **repositório
             separado** — aqui ficam apenas o contrato `.proto` e este ADR.
**Pré-requisitos**: ADR-0091 (gRPC Audit Exposer) em main — RPC
             `StreamAuditEvents`, auth `x-btv-internal-key`, porta
             `GRPC_PORT`.

---

## Contexto

ADR-0091 entregou o **produtor**: um servidor gRPC (Tonic) que faz streaming
de `FairnessAuditEvent` v1alpha a partir do tail dos JSONL locais. O
`ResilientAuditStreamConsumer` é o **primeiro consumidor externo** desse
stream — um cliente Java que alimenta dashboards, alertas e análise de viés
fora do processo do gateway.

O requisito central é **resiliência a desconexão**: o gateway pode reiniciar,
a rede pode particionar, e o servidor gRPC pode ficar temporariamente
indisponível — sem que o consumidor perca eventos já expostos nem reprocesse
em duplicidade descontrolada.

**Fronteira de tecnologia:** o consumidor Java depende **exclusivamente** do
contrato `audit_exposer.proto`. Não há acoplamento de código com o crate
Rust. O ciclo de release do gateway (performance nativa, segurança de baixo
nível) e o do consumidor Java (integrações Spring/SIEM/Kafka) são
independentes.

---

## Decisões

### D1 — Stack: `grpc-java` + `protobuf-java`, build Gradle (Kotlin DSL)

Classe `ResilientAuditStreamConsumer` standalone (construtor testável +
`main()`), sem framework de DI. Transport `io.grpc:grpc-netty-shaded`
(isolamento de classes do Netty). Geração de stubs via
`protobuf-gradle-plugin` a partir do `.proto` (consumido como submódulo Git
ou artefato de schema publicado em Nexus/Artifactory). Gradle pelo suporte
nativo superior ao plugin protobuf e à configuração de tasks customizadas.

### D2 — Resiliência: reconexão com backoff exponencial **+ jitter**

O consumidor mantém o stream aberto via `StreamObserver`. Em `onError`,
reconecta com backoff exponencial `100ms → 200ms → … → 30s` (cap).
`onCompleted` (servidor fechou normalmente) → reconecta com delay zero. Sem
estado de desistência — operação contínua.

**Jitter obrigatório (anti-*thundering herd*):** o delay aplica ruído
aleatório — `delay = min(cap, base · 2^tentativa) ± jitter`. Sem jitter,
milhares de consumidores que caíram juntos golpeariam o gateway sincronizados
a cada 30s, derrubando-o na recuperação. O jitter dispersa as reconexões.

### D3 — Cursor de retomada via `event_id` (UUID v7)

O `event_id` é UUID v7 (monotônico por timestamp). O consumidor persiste o
último `event_id` processado e, na reconexão, envia
`StreamRequest.resume_after_event_id` — o servidor avança o tail para logo
**após** esse evento, evitando reprocessamento.

**Contrato de entrega: at-least-once.** Se o cursor não for encontrado no
arquivo (rotação, tenant distinto), o servidor retoma do início do arquivo
atual. O consumidor **deve deduplicar por `event_id`** (idempotência no
handler). Não é exactly-once.

**Persistência atômica do cursor (anti-corrupção):** o cursor é gravado com
o padrão POSIX `write-temp + rename` —
`Files.move(tmp, dest, StandardCopyOption.ATOMIC_MOVE)`. Um `FileWriter`
ingênuo pode truncar o arquivo a 0 bytes num crash da JVM a meio da escrita;
um cursor vazio forçaria replay do ledger inteiro na reconexão (inundação +
CPU). O rename atômico garante que o cursor antigo só é substituído quando o
novo está fisicamente em disco.

### D4 — Handler de evento: interface + impl padrão SLF4J

Interface `AuditEventHandler { void onEvent(FairnessDecision event); }`.
Implementação padrão: log estruturado via SLF4J + Logback. Persistência em
banco, forwarding para Kafka ou envio a SIEM são **extensões por composição**
(fora do escopo deste ADR). O handler deve ser **não-bloqueante** — trabalho
pesado (I/O de rede/banco) roda em thread/scheduler separado para não represar
o stream gRPC.

### D5 — Auth: `ClientInterceptor`

Injeta `x-btv-internal-key` em toda chamada, com valor lido de
`BTV_INTERNAL_SECRET` (env) — nunca hardcoded. Mesmo segredo e mecanismo do
gateway (ADR-0089 §D2).

### D6 — Testes

`InProcessServerBuilder` (grpc-java) para testes sem porta real. Teste de
resiliência: simula `onError(StatusRuntimeException(UNAVAILABLE))` e verifica
reconexão após o backoff (com jitter). Teste de cursor: escrita truncada
valida o `ATOMIC_MOVE`. Teste de interceptor: confirma a injeção do header.

---

## Mudança neste repositório (pré-requisito do servidor)

Para D3, `StreamRequest` ganhou o campo (adição de tag nova → **não-quebrante**):

```protobuf
message StreamRequest {
  string tenant_id = 1;              // vazio = todos os tenants
  string resume_after_event_id = 2; // vazio = desde o início; cursor UUID v7
}
```

`grpc_exposer.rs` implementa `seek_after_event_id`: na primeira vez que vê
cada arquivo, se há cursor, varre do início até a linha do `event_id` e inicia
o tail logo após ela; cursor ausente → offset 0 (at-least-once). A busca é
linear O(tamanho), executada **uma vez por arquivo**. Mantida simples de
propósito: o tailer roda em task própria e lê o arquivo em modo leitura, sem
compartilhar lock com o `decide_handler` — não há, portanto, o risco de
degradar o p99 do hot path por essa varredura. Rotação agressiva de arquivos
(ops, ADR-0091 §D5) é o controle de tamanho.

---

## Consequências

**Positivas:**
- Resiliência real a reinício/partição com retomada precisa por cursor.
- Fronteira limpa: contrato `.proto` é a única dependência entre Rust e Java.
- Ciclos de release independentes (gateway nativo vs. consumidor JVM).

**Atenção / follow-ups:**
- **Contract drift sem CI unificado:** com o Java em outro repo, uma mudança
  quebrante no `.proto` passa verde no CI do gateway mas quebra o consumidor
  em runtime. **Recomendação:** adicionar uma etapa de *backward-compatibility
  check* (`buf breaking`) ao CI do gateway, travando merges que quebrem
  clientes gRPC existentes. (Fora do escopo deste ADR — decisão de CI própria.)
- **Busca linear do cursor:** sob arquivos muito grandes, o scan inicial custa
  O(tamanho). Mitigação atual = rotação por ops; otimização (índice por
  offset) só se houver evidência de gargalo.
- **at-least-once:** duplicatas são possíveis após reconexão; o handler Java
  deve ser idempotente por `event_id`.

---

## Próximo (pós-ADR-0092)

ADR-0093 — Alerting & Dashboarding: handlers que encaminham `FairnessDecision`
para SIEM (alertas em tempo real), dashboard de saúde (taxas de
REDACT/BLOCK, drift por tenant) e gatilho de retreino em *critical drift*.
Fecha o loop **Observar → Decidir → Agir → Aprender**.
