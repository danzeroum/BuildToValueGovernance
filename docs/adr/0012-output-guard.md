# ADR 0012 — Output Guard: Barreira de Saída do Kernel v4.0

**Status:** ✅ Aceito  
**Data:** 2026-05-28  
**Autores:** Engenharia de Plataforma e Governança do BTV  
**Revisores:** AI Squad — Arquiteta (Opus) + Reviewer (Opus)  
**Supersede:** ADR-012 v1.6 (Planejado) — stub de era chatbot, escopo incompatível com v4.0  
**Supersedido por:** —  
**Relacionados:** ADR 0011 (Policy Engine — entrada), ADR 0043 (Unified Verdict Identity), ADR 0063 (TechnicalEvidence 9596 bytes), ADR 0059 (Fronteira Rust/Python)

---

## Contexto

### Reorientação de Escopo (v1.6 → v4.0)

O stub original (`ADR-012 v1.6`) descrevia o Output Guard como um varredor de PII em respostas de Agente de IA entregues ao usuário final. Esse modelo é incompatível com a arquitetura do BTV v4.0, onde:

- O Kernel Rust não interage com usuários finais; ele emite **Verdicts** estruturados via fronteira FFI (JNI/gRPC) para o host Java
- O destinatário da saída é um **microsserviço interceptador** (`btv-interceptor`), não um cliente HTTP
- A ameaça relevante é **vazamento de metadados internos** (BiasDeclaration, modelo de equidade, PII residual no contexto de avaliação) através da fronteira de tipo FFI—não a alucinação de PII por um LLM

Auditoria forense em 2026-05-28 confirmou que o módulo `output_guard` já existe como implementação de produção no disco:

| Arquivo | Bytes | SHA | Função |
|:---|:---:|:---|:---|
| `rust/kernel/src/output_guard/sanitizer.rs` | 10.748 | `ff011ff3` | Sanitização e assinatura do Verdict |
| `rust/kernel/src/output_guard/injection_guard.rs` | 5.472 | `68230793` | Filtragem de metadados e detecção de injeção na saída |
| `rust/kernel/src/output_guard/mod.rs` | 222 | `92282e3b` | Interface pública do módulo (gateway de saída) |

Este ADR formaliza a decisão arquitetural que esses três artefatos implementam.

### Problema a Resolver

Sem uma especificação formal do Output Guard, três vetores de risco permanecem sem contrato arquitetural:

1. **Vazamento de metadados de viés:** A `BiasDeclaration` e as métricas de equidade (DIR de Rawls, PSI de Jonas) são dados internos de governância. Se vazarem para o host Java sem filtragem explícita, podem expor a lógica interna do modelo de decisão via logs ou tracing, violando a postura de Transparência Radical controlada do BTV.

2. **Integridade do Verdict em trânsito FFI:** A travessia da fronteira Rust/JVM é uma operação de serialização que pode introduzir mutações bit a bit não detectadas. Sem assinatura criptográfica do payload de saída, o host Java não pode verificar que o Verdict recebido é idêntico ao emitido pelo Kernel.

3. **Injeção em camadas downstream:** Um payload de saída mal-formado ou contendo payloads de injeção residuais pode propagar-se para sistemas downstream (SIEM, audit trail, UI de compliance) que consomem o output do interceptador.

---

## Decisão

Adotar o **Output Guard** como estágio obrigatório de pós-processamento, executado pelo Kernel Rust imediatamente antes da emissão do `Verdict` através da fronteira FFI. O módulo opera sob três responsabilidades arquiteturais distintas e inseparáveis.

---

## Arquitetura

### 1. Interface Pública e Gateway de Saída (`mod.rs`)

O `output_guard::mod.rs` atua como a **única porta de saída** entre o Kernel Rust e o Host Java. Nenhum `Verdict` pode cruzar a fronteira FFI sem ter sido processado pelo pipeline do Output Guard. A interface pública exporta exclusivamente:

```rust
// Única interface pública do módulo — tudo o que o gatekeeper.rs precisa conhecer
pub use sanitizer::sanitize_verdict;
pub use injection_guard::guard_output;
```

O `gatekeeper.rs` (17.206 bytes — orquestrador central do Kernel) é o único consumidor autorizado desta interface. A composição obrigatória é:

```rust
// Pipeline de saída obrigatório no gatekeeper.rs
let guarded  = output_guard::guard_output(raw_verdict)?;  // injection_guard.rs
let signed   = output_guard::sanitize_verdict(guarded)?;  // sanitizer.rs
// signed é o único payload autorizado a cruzar a fronteira FFI
```

Qualquer caminho de código que emita um Verdict sem passar por este pipeline constitui uma violação arquitetural detectada pelo linter de segurança e pelo `ci_gate_g0.py` (v2.2).

### 2. Sanitização e Assinatura Criptográfica do Verdict (`sanitizer.rs`)

O `sanitizer.rs` é responsável por duas operações sequenciais antes da travessia FFI:

**2a. Filtragem de PII Residual:** O contexto de avaliação (`EvaluationContext` — ADR 0011) pode conter campos demográficos usados na avaliação de equidade. O sanitizador garante que nenhum desses campos seja serializado no payload do Verdict entregue ao host Java. Apenas os campos canônicos do `TechnicalEvidence` (9.596 bytes — ADR 0063) são incluídos.

**2b. Assinatura HMAC-SHA256:** O payload final do Verdict recebe uma assinatura HMAC-SHA256 com a chave de sessão do tenant antes de cruzar a fronteira. O host Java verifica esta assinatura antes de processar o Verdict. Falha na verificação → Hard BLOCK com código `E150`.

```rust
// Contrato de saída: Verdict assinado é imutável e verificavel pelo host Java
let signature  = hmac_sha256(verdict_bytes, &session_key);
let signed_verdict = SignedVerdict { payload: verdict_bytes, hmac: signature };
```

### 3. Filtragem de Metadados e Proteção contra Injeção de Saída (`injection_guard.rs`)

O `injection_guard.rs` opera como um scanner de saída com duas responsabilidades:

**3a. Filtragem de `BiasDeclaration` e Metadados de Modelo:** As métricas de equidade internas (coeficientes DIR, PSI, FNR/FPR) são dados de governança interna. O `injection_guard.rs` remove esses campos do payload antes da entrega ao host Java, expondo apenas o `bias_risk_level` (enum: `LOW | MEDIUM | HIGH | CRITICAL`) — o nível de risco sem os coeficientes brutos.

**3b. Detecção de Payloads de Injeção Residuais:** O guard verifica se o payload de saída contém padrões de injeção que possam propagar-se para sistemas downstream. Qualquer anomalia no payload → Hard BLOCK com código `E150` e emissão de evento `BTV_OUTPUT_INJECTION_DETECTED` no ledger.

### 4. Contenimento de Pânico na Fronteira de Saída

Espelho do ADR 0011 (§3 — `catch_unwind` de entrada), o Output Guard encapsula o pipeline de saída em bloco de captura nativa:

```rust
let result = std::panic::catch_unwind(|| {
    let guarded = output_guard::guard_output(raw_verdict)?;
    output_guard::sanitize_verdict(guarded)
});
match result {
    Ok(Ok(signed)) => signed,
    Ok(Err(e))     => SignedVerdict::block_with_code(ErrorCode::E150, e),
    Err(_panic)    => SignedVerdict::block_with_code(ErrorCode::E150, "output_guard_panic"),
}
```

Qualquer instabilidade no pipeline de saída é retida na fronteira de tipo. O host Java sempre recebe um `SignedVerdict` — nunca um panic nativo descontrolado.

---

## Diagrama do Data Path Completo (ADR 0011 + ADR 0012)

```
[YAML Policy]  →  [PolicyEngine / AST BNF]  →  [EvaluationContext efêmero]  →  [Verdict bruto]
                        ADR 0011                                                      ↓
                                                                           [injection_guard.rs]
                                                                           [sanitizer.rs + HMAC]
                                                                                     ↓
[Host Java / btv-interceptor]  ←  [SignedVerdict]  ←  [fronteira FFI / catch_unwind]
                                      ADR 0012
```

O ADR 0011 governa a entrada (regras → decisão). O ADR 0012 governa a saída (decisão → entrega verificada). Juntos, fecham o ciclo de vida completo da transação dentro do enclave Rust.

---

## Consequências

### Positivas

- **Imutabilidade Verificada do Verdict:** A assinatura HMAC-SHA256 torna qualquer mutação bit a bit do Verdict detectável pelo host Java antes do processamento.
- **Princípio de Mínimo Privilégio na Saída:** O host Java recebe apenas o que precisa para agir — o Verdict e o `bias_risk_level` — sem acesso aos coeficientes de equidade internos ou ao contexto demográfico da avaliação.
- **Simétria Arquitetural:** O espelho `catch_unwind` de saída fecha o loop de segurança FFI iniciado pelo ADR 0011, tornando toda a fronteira Rust/JVM deterministicamente Fail-Closed.

### Trade-offs

- **Latência Adicional no Hot Path:** O pipeline de saída (filtragem + HMAC-SHA256) adiciona latência mensurável ao hot path transacional. O orbe de latência total (PolicyEngine + Output Guard) deve permanecer dentro do invariante `<50ms p99` do ADR 0011. Qualquer regressão de performance é detectada pelo `ci_gate_g0.py` v2.2.
- **Acoplamento com Gestão de Chaves:** A assinatura HMAC-SHA256 exige que a chave de sessão do tenant esteja disponível no escopo do Output Guard. O gerenciamento do ciclo de vida dessa chave é delegado ao módulo `keys.rs` (4.848 bytes — já presente no disco) e à política de rotação TEK do BTV-RUN-008.

---

## Validação

O Output Guard será considerado válido quando a suíte de testes em [`rust/kernel/tests/gatekeeper_pipeline.rs`](../../rust/kernel/tests/gatekeeper_pipeline.rs) atestar:

1. **Bloqueio de Verdict não assinado:** Nenhum Verdict sem HMAC válido passa pela fronteira FFI sem gerar `E150`.
2. **Ausência de PII no payload de saída:** Payloads contendo campos de `EvaluationContext` são filtrados antes da serialização.
3. **Ausência de coeficientes de equidade brutos:** `BiasDeclaration` e métricas DIR/PSI/FNR/FPR são removidos; apenas `bias_risk_level` (enum) é exposto.
4. **Contenção de pânico de saída:** Pânico no pipeline de saída é retido na fronteira e emite `E150` sem derrubar o microsserviço interceptador.

> **Referência física verificada:**  
> `rust/kernel/src/output_guard/sanitizer.rs` — SHA `ff011ff3`, 10.748 bytes  
> `rust/kernel/src/output_guard/injection_guard.rs` — SHA `68230793`, 5.472 bytes  
> `rust/kernel/src/output_guard/mod.rs` — SHA `92282e3b`, 222 bytes  
> `rust/kernel/tests/gatekeeper_pipeline.rs` — SHA `74beccf4`, 5.613 bytes  
> Todos confirmados no HEAD `5147a98` em 2026-05-28.

---

## Registro de Revisões

| Versão | Data | Alteração |
|:---|:---|:---|
| v0.1 (stub) | anterior a 2026-01-01 | Placeholder de era chatbot. Escopo: varredor de PII em resposta LLM. Incompatível com BTV v4.0. |
| v1.0 | 2026-05-28 | Reescrita total. Escopo reorientado para enclave de governança transacional FFI Rust/JVM. Auditoria forense confirmou 16.442 bytes de implementação real em `output_guard/`. |
