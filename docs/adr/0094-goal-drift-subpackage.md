# ADR-0094: Decomposição de `goal_drift_sentinel.py` em subpacote

**Status**: ✅ ACEITO (implementado)
**Data**: 29 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `python/buildtovalue/governance/goal_drift/` (novo subpacote);
             `goal_drift_sentinel.py` vira facade de compatibilidade.
**Pré-requisitos**: nenhum (refatoração interna, zero mudança de comportamento).

---

## Contexto

`governance/goal_drift_sentinel.py` (24,5 KB) concentrava num único módulo:
constantes + enums + dataclasses, funções de scoring sem estado, e a classe
`GoalDriftSentinel` (detecção temporal por sessão, HMAC, fail-secure). Isso
viola as diretrizes de granularidade da República Algorítmica.

## Decisão

Extrair para o subpacote `goal_drift/` com fronteiras por responsabilidade:

- `_types.py` — constantes (`DRIFT_SCORE`, …), enums (`DriftAction`,
  `DriftDirection`), dataclasses (`DriftReport`, `_SessionWindow`,
  `ModelPerformanceReport`). Folha da árvore de imports.
- `_scorer.py` — funções puras de scoring (`_compute_trend_pct`, `_is_burst`,
  `_detect_asymmetric_pressure`, `_compute_drift_direction`,
  `_compute_pressure_accumulation`). Depende apenas de `_types`.
- `_detector.py` — a classe `GoalDriftSentinel`. Depende de `_types` + `_scorer`.
- `__init__.py` — reexporta a API pública.

`goal_drift_sentinel.py` passa a ser **facade**: reexporta a API pública e os
helpers de scoring usados por testes legados, com `__all__` explícito (sem
`import *` genérico). **Critério de aceite**: `from
buildtovalue.governance.goal_drift_sentinel import GoalDriftSentinel`
(e todos os símbolos previamente públicos) continua funcionando.

Regra de dependência interna (sem ciclos): `_types ← _scorer ← _detector ← __init__`.

## Desvio documentado

A classe `GoalDriftSentinel` permanece **coesa** em `_detector.py` (≈300
linhas, acima do alvo de 200). Fracioná-la quebraria a coesão do estado
(ring buffer por sessão + HMAC + fail-secure) com risco de regressão num
caminho assinado e fail-secure. A separação tipos/scoring/detector entrega o
valor de manutenibilidade sem esse risco. Tipos puros e scoring isolados são
≤120 e ≤90 linhas respectivamente.

## Invariantes preservadas (Jonas)

- Rastreabilidade imutável de anomalias: ring buffer com evicção via
  `SessionManager` (LRU+TTL), nunca truncamento silencioso.
- Fail-secure: exceção interna → `ESCALATE_HUMAN` assinado (HMAC-SHA256),
  jamais silêncio.

## Consequências

- Zero mudança de comportamento; suíte de drift (58 testes) passa sem alteração.
- `mypy --strict` limpo nos 3 novos módulos (zero `Any`).
- Imports externos (`api/app.py`, `agentic/`, testes) inalterados.
