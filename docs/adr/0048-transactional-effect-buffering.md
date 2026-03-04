# ADR-0048 — Transactional Effect Buffering (PROP-029)

**Status:** APROVADO
**Data:** 2026-03-04
**Autores:** Arquiteta (design), Dev Rust (implementação)
**Desbloqueio:** PROP-029 EffectLog
**Refs:** paper 216 (Atomix, ICLR 2026), paper 240 (GIRA, ICLR 2026)
**ADRs relacionados:** ADR-0004 (Immutable Ledger), ADR-0042 (Policy-as-Code v2)

---

## Contexto

O BTV aprova decisões mas não controla o **commit** da ação. Ações irreversíveis
(delete, send email, API write) são externalizadas imediatamente após aprovação do
Gatekeeper. Se um erro for detectado após execução, o dano é permanente e o Ledger
registra apenas o post-mortem.

**Evidência empírica (paper 216 — Atomix):**
- Tx-Full: 37–57% taxa de sucesso sob falhas injetadas vs. 0–7% sem transações
- Modo No-Frontier (retry+compensação sem fronteiras): apenas 7.8% no WebArena
- Fronteiras são o mecanismo-chave, não apenas o buffering
- Overhead: 7.7µs por step — cabe no budget de 50ms p99 com folga

**Evidência empírica (paper 240 — GIRA):**
- Blast radius reduzido de 0.736 → 0.145 com safety gate multicamada

**Limitação do Atomix como referência:**
Atomix é implementação single-process Python sem crash safety real. O BTV implementa
a versão Rust com durabilidade via WAL existente (ADR-0004) — vantagem arquitetural
significativa que este ADR formaliza.

---

## Decisões

### D1 — Taxonomia bidimensional de efeitos

**Decisão:** Adotar matriz `Reversibility × Temporality` em vez de enum linear.

**Justificativa:** O Atomix revelou que reversibilidade e temporalidade são dimensões
ortogonais. Um efeito pode ser `Reversible` mas já `Externalized` (ex: API call com
rate limit consumido). Um enum linear não captura esta distinção — levaria a over-block
de efeitos externos reversíveis e under-block de efeitos internos irreversíveis.

```rust
// rust/kernel/src/ledger/effect_log.rs
pub enum Reversibility {
    Reversible,
    ReversibleWithCost,  // ex: API call com rate limit consumido
    Irreversible,
}

pub enum Temporality {
    Bufferable,    // pode ser retido até frontier confirmar
    Externalized,  // efeito já visível fora do sistema
}
```

**Alternativas rejeitadas:**
- Enum linear `Safe/Risky/Dangerous`: não captura temporalidade → over-simplification
- Score numérico 0.0–1.0: contínuo dificulta decisão binária Buffer/Execute → rejeitado

### D2 — Ring buffer estático com capacidade fixa

**Decisão:** `EFFECT_RING_CAPACITY = 64`, constante em tempo de compilação, pré-alocado
no stack. Zero alloc no hot path.

**Justificativa:** Invariante BTV: zero heap no hot path. Capacity 64 cobre workflows
de agente típicos (paper 216: experimentos com até ~20 steps por tarefa) com margem 3×.

```rust
pub struct EffectLog {
    ring: [EffectEntry; EFFECT_RING_CAPACITY],  // stack-allocated
    head: AtomicUsize,
    // sem Vec, sem Box, sem String
}
```

**Restrição:** `EffectEntry` deve ser `Copy + Sized` — sem heap interno.
HMAC-SHA256 em cada `EffectEntry` (Jonas: responsabilidade por cada efeito individual).

### D3 — Frontier per-resource (não global)

**Decisão:** Fronteiras de confirmação são por recurso (`resource_id: [u8; 32]`),
armazenadas em `_reserved_metadata` do `TechnicalEvidence`, não em `AtomicU64` global.

**Justificativa:** Paper 216 demonstra que frontier global cria gargalo em workflows
paralelos com múltiplos recursos. Frontier per-resource permite confirmação independente:

```rust
pub struct ResourceFrontier {
    resource_id: [u8; 32],   // BLAKE3 hash do recurso
    epoch:       AtomicU64,
    confirmed:   AtomicBool,
}
```

**Armazenamento:** `_reserved_metadata[41..200]` — fora dos offsets já alocados:
- `[0..4]`   = type tag (PROP-030 RecoveryEngine)
- `[8..40]`  = skill_hash (PROP-031)
- `[40]`     = flags byte bit 0 = policy_drift_detected (PROP-038)
- `[41..200]` = **EffectLog frontier data** (este ADR)

**Invariante de bytes:** `TechnicalEvidence` permanece em 9600 bytes fixos.
Nenhum campo novo é adicionado ao struct — apenas uso de `_reserved_metadata`.

### D4 — Protocolo de compensação: handler fail = ABORT

**Decisão:** Se o handler de compensação falhar, a ação é `ABORT` (não retry, não ignore).
ABORT é registrado no Ledger com HMAC-SHA256 e marcado como contestável (SLA 24h).

**Justificativa (Jonas + fail-secure):** A responsabilidade pelo efeito não pode ser
transferida silenciosamente. Um handler que falha indica estado inconsistente — a
decisão correta é parar e registrar, nunca prosseguir.

**Timeout hard-cap:** 40ms total para buffer → frontier → confirm. Se expirar: ABORT
automático. Este valor preserva 10ms de folga no budget de 50ms p99.

```rust
// Em gatekeeper.rs: verificar (Reversibility, Temporality) antes de executar
match (effect.reversibility, effect.temporality) {
    (Irreversible, _) => effect_log.buffer_and_await_frontier(effect, 40_ms)?,
    (_, Externalized) => effect_log.record_immediate(effect)?,
    _                 => effect_log.buffer(effect)?,
}
```

### D5 — Vantagem BTV sobre Atomix: WAL existente

**Decisão:** Usar o WAL do Ledger (ADR-0004) como mecanismo de durabilidade do
`EffectLog`, em vez de implementar crash recovery próprio.

**Justificativa:** Atomix (paper 216) opera in-memory sem durabilidade real — o próprio
paper admite a limitação. O BTV tem WAL imutável já implementado. Cada `EffectEntry`
bufferizado é gravado no WAL antes do commit da ação — se o processo crashar, o log
permite replay determinístico na recovery.

---

## Consequências

### Positivas
- Erros fatais tornam-se erros recuperáveis
- Blast radius controlado por frontier per-resource
- Zero custo adicional de durabilidade (WAL existente)
- Overhead 7.7µs (medido pelo paper 216) << budget de 50ms

### Negativas / Trade-offs
- `EffectEntry` limitado a `Copy + Sized` → sem strings no hot path
- Frontier per-resource requer gestão de `_reserved_metadata[41..200]`
- Implementação mais complexa que enum linear — justificada pela evidência empírica

### Checklist de implementação (PROP-029)
- [ ] `EFFECT_RING_CAPACITY = 64` constante em tempo de compilação
- [ ] Zero alloc: sem `Vec`, `Box`, `String` em `EffectEntry`
- [ ] Frontier per-resource em `_reserved_metadata[41..200]`
- [ ] Timeout 40ms hard-cap; ABORT automático em expiração
- [ ] `TechnicalEvidence` mantém 9600 bytes após adição (assert em CI)
- [ ] HMAC-SHA256 em cada `EffectEntry`
- [ ] WAL integration: `EffectEntry` gravado antes do commit da ação
- [ ] Handler fail → ABORT registrado no Ledger, contestável (SLA 24h)

---

## Mapeamento de arquivos

```
rust/kernel/src/ledger/effect_log.rs       — novo módulo
rust/kernel/src/gatekeeper.rs              — verificar (Reversibility, Temporality)
data/policies/effect_classification.yaml  — catálogo tools por classe
```
