---
title: Anatomia da Evidência
---

# Anatomia da `TechnicalEvidence`

A `TechnicalEvidence` é o registro imutável que o BuildToValue produz para cada
decisão do gateway. Ela é simultaneamente **prova** (auditável fora do sistema)
e **artefato operacional** (consumido pelos componentes internos).

## Dois tamanhos, uma decisão

A struct existe em **duas formas canônicas**, cada uma servindo um propósito
arquitetural distinto. Não é bug — é decisão deliberada, registrada no
[ADR-063](../../adr/0063-technical-evidence-size-invariant.md) e explicada em
profundidade no [`CHANGELOG_PHILOSOPHICAL.md`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/CHANGELOG_PHILOSOPHICAL.md).

**Os tamanhos exatos são extraídos do código Rust e exibidos na
[referência técnica gerada](../reference/index.md).** Não digite os números
manualmente em nenhum lugar — a validação `scripts/validate_invariants.py`
falhará no CI se você fizer isso.

### Forma operacional (Kernel)

- Definida em [`rust/kernel/src/core/types.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/kernel/src/core/types.rs).
- Inclui campos reservados para atestação de hardware (C8) e metadados de
  habilidade (Prop-031).
- Validada em tempo de compilação via `const_assert_eq!`.

### Forma constitucional (Wire)

- Definida em [`rust/btv-types/src/lib.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/btv-types/src/lib.rs).
- Produzida por `Verdict::to_technical_evidence()`.
- É o formato transmitido entre componentes — é **isto** que você consome se
  integra com o gateway.

## Como decidir qual usar

| Você está... | Use a forma... |
| --- | --- |
| Integrando com o gateway via HTTP/SDK | **Constitucional** (wire) |
| Verificando uma prova fora do navegador via `btv-cli` | **Constitucional** (wire) |
| Contribuindo para o kernel Rust | **Operacional** (kernel) |
| Lendo documentação que diz "o tamanho" sem qualificar | **Pare** — peça a qualificação |

## Anti-padrão: o número avulso

Toda referência ao tamanho da evidência **deve** vir qualificada
(operacional/constitucional, kernel/wire). Citações sem qualificador devem ser
tratadas como **incompletas** — é exatamente esse anti-padrão que motivou a
existência do `CHANGELOG_PHILOSOPHICAL.md`.
