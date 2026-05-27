---
title: "Tutorial 04 — Propor uma Política (Legislador / Juiz)"
---

# Tutorial 04 — Propor uma Política

Trilhas: **Legislador** (propõe ADRs e políticas YAML) e **Juiz** (calibra
thresholds éticos, avalia contestações).

## Como Legislador

1. Leia o [Protocolo CAP](../cap-protocol.md).
2. Copie o template:

   ```bash
   cp docs/adr/0000-adr-index.md docs/adr/NNNN-titulo-kebab-case.md
   ```

3. Preencha as seções obrigatórias: Contexto, Decisão, Consequências,
   Invariantes a verificar.
4. Abra PR contra `main`. O CI roda `scripts/validate_invariants.py` e
   `mkdocs build --strict`.

## Como Juiz

1. Identifique um threshold ético na configuração YAML
   (`docs/adr/0038-ethical-context-engine-v4.md` documenta o motor).
2. Submeta a proposta de calibração via PR, **acompanhada** de:
   - Evidências do ledger que justificam a mudança.
   - Análise de impacto em fluxos existentes
     ([sizing-guide](../compliance/sizing-guide.md)).
3. Casos de contestação são avaliados via `ContestabilityLoop`
   ([conceito](../concepts/contestability-loop.md)).

## Regra de ouro

Toda emenda à constituição (mudança em ADR ou threshold) **deve** referenciar a
evidência que a motivou. Sem rastro, sem mudança.
