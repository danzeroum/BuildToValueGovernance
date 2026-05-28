# ADR-0082: API Evolution & Deprecation Policy

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta (validado por revisões consolidadas)
**Impacto**: `rust/kernel/src/api/`, `docs/api-reference.md`,
             todos os SDKs (Python, Java futuro), todos os tenants integrados

## Contexto

O BTV expõe contratos de API que clientes regulados (bancos, healthtechs,
seguradoras) integram em produção. Uma mudança silenciosa em
`ExplainDecision`, `BiasDeclaration` ou na estrutura de `TechnicalEvidence`
pode derrubar integrações em vigor, gerando violação do
**SLA de contestabilidade de 24h** (ADR-0017) e exposição regulatória
do controlador (LGPD Art. 20).

Hoje não há política formal de evolução, e a regra de fato — "nunca
remover campos" — é insuficiente: campos adicionados como obrigatórios
quebram clientes que rodam em versões anteriores tão violentamente
quanto remoções.

## Decisão

### 1. Classificação de Mudanças

| Tipo | Exemplo | Ação requerida |
|------|---------|----------------|
| **Não-breaking** | Adicionar campo opcional, novo endpoint, novo header | Liberar em `/v1/` |
| **Breaking** | Remover campo, alterar tipo, alterar semântica, mudar status code | Novo prefixo `/v2/` + ciclo de deprecação (≥90 dias) |
| **Emergency** | Patch crítico de segurança | Aplicar imediatamente em todas as versões vivas; postmortem público em 7 dias |

### 2. Cláusula de Compatibilidade (Invariante)

> **Todo campo adicionado a `ExplainDecision`, `BiasDeclaration` ou
> `EthicalError` após v1.0 deve ser `Option<T>` em Rust e
> `@JsonProperty(required = false)` no cliente Java. Mudança de semântica
> de campo existente equivale a breaking change e exige major version.**

Isto protege clientes bancários e de saúde de falhas silenciosas durante
upgrades. Construtores que recebem o novo campo via parâmetro nomeado
opcional preservam call sites antigos.

### 3. Imutabilidade dos Campos de Auditabilidade

`ExplainDecision` e `BiasDeclaration` **nunca perdem campos** — apenas
ganham. Remoção de qualquer campo desses tipos é proibida por este ADR,
mesmo em major version. Auditoria forense histórica exige que registros
antigos permaneçam interpretáveis indefinidamente (ADR-0052).

### 4. Ciclo de Deprecação

Quando um endpoint ou campo é descontinuado:

1. Resposta passa a incluir header `Deprecation: date="YYYY-MM-DD"`.
2. Resposta passa a incluir header `Sunset: date="YYYY-MM-DD"`
   (RFC 8594), com **mínimo 90 dias** após `Deprecation`.
3. Notificação ativa via webhook `POST /tenant/webhooks/deprecation`
   com payload contendo `endpoint`, `deprecation_date`, `sunset_date`,
   `migration_url`.
4. Documentação de migração publicada **antes** do `Sunset`.
5. Após `Sunset`, endpoint responde `410 Gone` com `EthicalError`
   apontando para a versão substituta.

### 5. Filosofia de Execução do Registry (`EthicsPluginRegistry`)

O `EthicsPluginRegistry` (definido em `rust/kernel/src/ethics_plugin.rs`)
**mantém short-circuit fail-secure**: a primeira decisão `Block` ou
qualquer `Err` de plugin interrompe imediatamente a cadeia de
`validate()`. Plugins subsequentes **não são executados**.

**Justificativa.** O argumento de "executar todos para coletar todos os
motivos" (visando LGPD Art. 20) conflita diretamente com o invariante
nuclear do BTV. Um plugin que retornou `Block` com estado interno
corrompido pode, se a cadeia continuar, propagar corrupção e gerar
laudos contraditórios — pior que o problema que tenta resolver.

A explicabilidade exigida pelo Art. 20 é atendida por dois mecanismos
**sem violar fail-secure**:

1. O `Registry` chama `explain()` em **todos** os plugins antes de
   `validate()`. As `BiasDeclaration` declaradas ficam disponíveis
   integralmente no `RegistryResult.declarations`, independentemente
   de quem bloqueou.
2. O `RegistryResult` inclui `skipped_plugins: Vec<&'static str>` com
   os IDs dos plugins não executados — auditável e explícito para o
   revisor humano.

### 6. Enforcement Automatizado

A conformidade desta política será verificada automaticamente pelo
`btv-validator` (ADR futuro) integrado ao CI:

- Diff de schema entre PRs: rejeita campos novos não-`Option<T>`.
- Diff entre `ExplainDecision`/`BiasDeclaration` versões: rejeita remoções.
- Headers `Deprecation`/`Sunset`: valida prazo mínimo de 90 dias.

Até o `btv-validator` existir, a regra é enforçada manualmente em code
review com referência a este ADR.

## Consequências

**Positivas**

- Clientes têm contrato previsível: sabem exatamente quando precisam migrar.
- Ledger forense permanece consultável em qualquer versão histórica.
- SLA de contestabilidade (24h) preservado entre versões.
- Short-circuit do Registry mantém invariante de fail-secure intocado.
- Auditoria LGPD Art. 20 atendida via `declarations` + `skipped_plugins`.

**Negativas / Custos**

- Maior disciplina exigida em PRs de schema (custo de revisão).
- Ciclo de 90 dias prolonga obsolescência de código.
- Tipos com muitos campos opcionais crescem com o tempo (mitigado por
  major versions periódicas que limpam o histórico opcional).

## Referências

- RFC 7807 — Problem Details for HTTP APIs
- RFC 8594 — The `Sunset` HTTP Header Field
- ADR-0010 — BiasDeclaration Mandate
- ADR-0017 — Contestability Loop
- ADR-0052 — Forensic Audit Storage
- `docs/API_ETHICS_GUIDE.md`
