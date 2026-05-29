# ADR-0093: Decomposição de `api/app.py`

**Status**: 🟡 PARCIAL (Fase 1 implementada; Fase 2 estagiada)
**Data**: 29 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `python/buildtovalue/api/_models.py` (novo); `app.py` reduzido.
**Pré-requisitos**: ADR-0094/0095 (provam o padrão facade/subpacote).

---

## Contexto

`api/app.py` (~92 KB / 2240 linhas) acopla sete responsabilidades: modelos
Pydantic, camada SQLite, helpers de guard, pipeline de decisão (`decide`,
`_decide_*`), `@asynccontextmanager lifespan`, configuração de app/CORS e
rotas inline residuais. O alvo é um orquestrador puro de montagem (~80 linhas).

## Decisão

### Fase 1 — Extração de contratos de dados (IMPLEMENTADA)

Os 16 modelos do cluster principal (`DecideRequest`, `BiasDeclaration`,
`DecideResponse`, `MultiDecide*`, `Appeal*`, `RiskClassifyRequest`,
`ComplianceRequest`, `Threat*`, `FRIARequest`) migram para `api/_models.py`.
`app.py` reimporta-os, preservando `from buildtovalue.api.app import X`.
Princípio: **modelos não conhecem regras**; apenas regras consomem modelos.
`mypy --strict` limpo em `_models.py` (zero `Any`; `dict`/`list` parametrizados).

### Fase 2 — Lifespan + pipeline + rotas (ESTAGIADA)

Extrair `lifespan`, o pipeline `decide()`/`_decide_*` e as rotas inline para
`_lifespan.py`, `_decide_pipeline.py` e novos routers exige **migrar 9
singletons hoje mantidos como variáveis-módulo** (reatribuídas via `global` no
`lifespan`: `_ethical_engine`, `_trust_calculator`, `_goal_drift_sentinel`,
`_contestability_loop`, `_profile_manager`, `_sector_loader`, `_slm`,
`_cross_agent`, `_delegation_ledger`) para `app.state`, e reescrever ~12
helpers que hoje leem esses globals diretamente.

Essa reescrita toca o **hot path** de `/v1/decide` (invariante <50ms p99) e a
assinatura HMAC do verdict. Para não acoplar esse risco à decomposição de
governança (ADR-0094/0095), a Fase 2 é deliberadamente estagiada para um PR
dedicado e revisado isoladamente, consumindo estado **exclusivamente** via
`request.app.state` / `Depends` (eliminando a necessidade de importar `app`).

## Consequências

- Fase 1: `app.py` 2240 → ~2120 linhas; contratos isolados e tipados;
  back-compat total; suíte de API passa sem alteração.
- Fase 2 pendente: o alvo de ~80 linhas só é atingido após a migração
  segura dos singletons para `app.state`.
- Invariante Rawls: `DecideRequest` chega com `session_id` opaco (sem
  metadados de identidade), preservando o ambiente limpo de inferência ética
  quando `decide()` for futuramente isolado.

## Limite inviolável

`rust/kernel/` permanece intocado. A asserção de 9632 bytes de
`TechnicalEvidence` (ADR-063) segue como âncora canônica.
