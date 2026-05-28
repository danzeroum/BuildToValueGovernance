# ADR 0013 — Deobfuscator Chaining v2

**Status:** ✅ Aceito  
**Data:** 2026-05-28  
**Versão:** v2.0.0  
**Autores:** AI Squad (Arquiteta + Reviewer)  
**Âncora física:** `rust/kernel/src/deobfuscator/` (47.852 bytes)

---

## Contexto

Atores maliciosos frequentemente submetem ao kernel BTV payloads obfuscados para evadir validadores de políticas. Técnicas comuns incluem encoding Base64, encoding hexadecimal, substituição leetspeak (l33tsp34k) e variações Unicode homoglíficas (ex.: U+0430 CYRILLIC SMALL LETTER A no lugar de ASCII `a`). Sem uma camada de normalização antes do pipeline de avaliação, o `PolicyEngine` (ADR 0011) avaliaria o texto cifrado em vez do texto de ataque real, tornando os guardrails ineficazes.

Este ADR documenta a decisão de implementar um **pipeline composicional de deobfuscação** executado no Kernel Rust antes de qualquer avaliação de política, garantindo que o `EvaluationContext` receba sempre texto canônico.

---

## Decisão

Adotar a arquitetura de **Chaining v2**: um pipeline sequencial e composicional de deobfuscadores especializados, orquestrado por `chain.rs`, que transforma o input bruto em representação canônica antes de qualquer avaliação.

### Módulos físicos do pipeline

| Arquivo | Bytes | Responsabilidade |
|:---|:---:|:---|
| [`chain.rs`](../../rust/kernel/src/deobfuscator/chain.rs) | 14.476 | Orquestrador do pipeline — composição sequencial dos deobfuscadores |
| [`normalizer.rs`](../../rust/kernel/src/deobfuscator/normalizer.rs) | 22.706 | Normalização Unicode NFKC, canonicalização de homoglíficos e whitespace |
| [`base64.rs`](../../rust/kernel/src/deobfuscator/base64.rs) | 4.023 | Detecção e decodificação de payloads Base64 |
| [`hex.rs`](../../rust/kernel/src/deobfuscator/hex.rs) | 3.675 | Detecção e decodificação de encoding hexadecimal |
| [`leetspeak.rs`](../../rust/kernel/src/deobfuscator/leetspeak.rs) | 2.417 | Reversão de substituição l33tsp34k para ASCII canônico |
| [`mod.rs`](../../rust/kernel/src/deobfuscator/mod.rs) | 555 | Contrato público do módulo — expõe `DeobfuscatorChain` |

**Total do módulo: ~47.852 bytes.**

### Fluxo de execução

```
[Input bruto do agente/usuário]
        |
        ▼
[base64.rs]   → detecta e decodifica encoding Base64
[hex.rs]      → detecta e decodifica encoding hexadecimal
[leetspeak.rs]→ reverte substituições l33tsp34k
        |
        ▼
[chain.rs] — orquestra a sequência, aplica iterativamente até estabilização
        |
        ▼
[normalizer.rs] — NFKC + canonicalização final de homoglíficos Unicode
        |
        ▼
[EvaluationContext canônico] → PolicyEngine (ADR 0011)
```

O design de **iteração até estabilização** em `chain.rs` é crítico: um ataque pode ser duplamente encodado (Base64 de hex). O pipeline reaplica os deobfuscadores até que nenhuma transformação adicional seja possível, garantindo que ataques aninhados sejam completamente revelados.

---

## Invariantes Técnicos

- **Zero heap no hot path:** os deobfuscadores operam sobre slices e retornam `Cow<str>` para evitar alocações desnecessárias.
- **Fail-Secure:** qualquer erro de decodificação (ex.: Base64 malformado) retorna o input original sem pânico, delegando ao PolicyEngine a decisão sobre o texto bruto.
- **Composicionalidade:** cada deobfuscador implementa o trait `Deobfuscator`, permitindo inclusão ou exclusão de estágios via configuração de política (ADR 0006 / ADR 0042).
- **Idempotência:** aplicar o pipeline duas vezes ao mesmo input produz o mesmo resultado.

---

## Relação com outros ADRs

| ADR | Relação |
|:---|:---|
| ADR 0011 — Policy Engine | Consumidor direto: recebe o `EvaluationContext` normalizado |
| ADR 0028 — Heuristic Prompt Injection Detector | Opera sobre o texto já normalizado pelo Deobfuscator |
| ADR 0012 — Output Guard | Fronteira de saída; este ADR governa a fronteira de entrada |
| ADR 0006 / ADR 0042 — Policy as Code v1/v2 | Configuração de quais estágios do pipeline estão ativos por tenant |

---

## Consequências

**Positivas:**
- Ataques de evasão por encoding são neutralizados antes de chegarem ao PolicyEngine.
- Pipeline extensível: novos vetores de obfuscação (ex.: Unicode bidi override) podem ser adicionados como novos estágios sem alterar os existentes.
- Auditabilidade: o `chain.rs` registra cada transformação aplicada como parte da `TechnicalEvidence` (ADR 0005).

**Negativas / Trade-offs:**
- Latência adicional no hot path proporcional ao número de estágios ativos. Mitigado pela ausência de heap allocation e pela execução em Rust nativo.
- Risco de falso-positivo em conteúdo legítimo encodado (ex.: código-fonte em Base64). Mitigado por threshold de confiança configurável no `chain.rs`.

---

## Auditoria

Este ADR foi promovido de stub (369 bytes) para Aceito após inspeção física do diretório `rust/kernel/src/deobfuscator/` em 2026-05-28. A implementação de 47.852 bytes confirma maturidade arquitetural suficiente para formalização como decisão de governança.
