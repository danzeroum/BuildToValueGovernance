# ADR 0015 — Interceptor Hooks

**Status:** ✅ Aceito  
**Data:** 2026-05-28  
**Versão:** v1.0.0  
**Autores:** AI Squad (Arquiteta + Reviewer)  
**Âncora física:** `rust/kernel/src/interceptor/` (13.311 bytes)

---

## Contexto

O BTV v4.0 precisa injetar governança em dois pontos distintos do fluxo de execução agentic:

1. **Chamadas de ferramenta (tool-calls):** Quando um agente de IA decide invocar uma ferramenta externa (ex.: execução de código, acesso a banco de dados, chamada de API), o kernel deve interceptar e avaliar a intenção antes da execução.
2. **Fronteira gRPC/FFI:** Quando o host Java repassa requests ao kernel Rust, o ponto de interceptação determina onde a avaliação de política é injetada no ciclo de vida da requisição.

Sem pontos de interceptação explícitos e verificáveis no código, a governança seria aplicada apenas no nível de aplicação (Python), deixando o kernel Rust sem capacidade de bloquear operações perigosas diretamente no data path.

Este ADR documenta a decisão arquitetural de usar **hooks explícitos** (`hooks.rs`) e uma **tela de ferramentas** (`tool_screen.rs`) como os dois mecanismos de injeção de governança no kernel.

---

## Decisão

Manter dois sub-módulos distintos dentro de `interceptor/`, com responsabilidades não sobrepostas:

### Módulos físicos

| Arquivo | Bytes | Responsabilidade |
|:---|:---:|:---|
| [`hooks.rs`](../../rust/kernel/src/interceptor/hooks.rs) | 8.167 | Pontos de intercepção no ciclo de vida da requisição: `pre_eval`, `post_eval`, `on_block`, `on_allow` |
| [`tool_screen.rs`](../../rust/kernel/src/interceptor/tool_screen.rs) | 4.812 | Triagem de tool-calls agentic: avalia se a ferramenta solicitada é permitida pela política ativa do tenant |
| [`mod.rs`](../../rust/kernel/src/interceptor/mod.rs) | 332 | Contrato público do módulo — expõe `InterceptorHooks` e `ToolScreen` |

**Total do módulo: ~13.311 bytes.**

### Contrato arquitetural

```
[Request inbound — gRPC/FFI]
          |
          ▼
[hooks.rs: pre_eval hook]
   → Injeta metadados de sessão no EvaluationContext
   → Registra timestamp de entrada na TechnicalEvidence
          |
          ▼
[tool_screen.rs] ← ativado apenas se request contiver tool-call
   → Consulta PolicyEngine: esta ferramenta está permitida?
   → BLOCK imediato se ferramenta não autorizada (fail-secure)
          |
          ▼
[Pipeline de avaliação principal]
   → Deobfuscator (ADR 0013) → PolicyEngine (ADR 0011)
          |
          ▼
[hooks.rs: post_eval hook / on_block / on_allow]
   → Fecha registro de evidência forense
   → Dispara webhook se configurado (ADR 0026)
```

---

## Invariantes Técnicos

- **Hooks são obrigatórios:** nenhum request pode completar o ciclo de avaliação sem passar pelos hooks `pre_eval` e `post_eval`. A ausência de registro de hook é tratada como `BLOCK` (fail-secure).
- **`tool_screen.rs` é fail-secure:** qualquer ferramenta não explicitamente listada na política ativa do tenant é bloqueada por padrão (`deny-by-default`).
- **Zero side effects em `pre_eval`:** o hook de pré-avaliação é read-only em relação ao payload — apenas adiciona metadados, nunca modifica o conteúdo da requisição.
- **Isolamento de tenant:** `hooks.rs` extrai e valida o `tenant_id` do JWT antes de qualquer injeção de contexto, prevenindo cross-tenant pollution (código de erro `E120`, BTV-RUN-008).

---

## Relação com outros ADRs

| ADR | Relação |
|:---|:---|
| ADR 0013 — Deobfuscator Chaining v2 | Executado após `pre_eval`; recebe o contexto já enriquecido pelos hooks |
| ADR 0011 — Policy Engine | Consultado por `tool_screen.rs` para decisão de allow/block em tool-calls |
| ADR 0054 — Agentic Layer | Consumidor direto de `tool_screen.rs`; define o catálogo de ferramentas disponíveis |
| ADR 0029 — External Agent PDP | Coordenação com hooks para requests de agentes externos |
| ADR 0026 — Webhook Notifications | Disparado por `post_eval` / `on_block` hooks |

---

## Consequências

**Positivas:**
- Governança injetada diretamente no kernel Rust, não dependente da camada Python para bloquear tool-calls perigosas.
- Auditabilidade completa: cada request tem registro de entrada e saída via hooks, com TechnicalEvidence (ADR 0005) fechada em ambos os extremos.
- Extensibilidade: novos hooks podem ser adicionados sem alterar o pipeline principal.

**Negativas / Trade-offs:**
- Latência de ~2-5ms por request para execução dos hooks (estimado; dentro do budget de 50ms p99 do ADR 0001).
- `tool_screen.rs` requer que o catálogo de ferramentas esteja carregado em memória — acoplamento com o ciclo de reload de políticas (ADR 0064).

---

## Auditoria

Este ADR foi promovido de stub (341 bytes) para Aceito após inspeção física do diretório `rust/kernel/src/interceptor/` em 2026-05-28. O módulo `hooks.rs` (8.167 bytes) e `tool_screen.rs` (4.812 bytes) confirmam implementação operacional dos dois mecanismos de interceptação.
