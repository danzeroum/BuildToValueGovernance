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

## Fase 2 — execução incremental via shim provisório

A migração para `app.state` é executada **incrementalmente** através de um shim
provisório; **a remoção do shim é o critério de conclusão da Fase 2**. Os 9
singletons têm **105 read-sites** em `app.py` — migrá-los num único PR sobre o
hot path HMAC-assinado é risco desproporcional. Sequência atômica (suíte verde
e commit por passo):

- **Passo 1 (feito):** `lifespan` → `api/_lifespan.py`. O startup reinjeta os 11
  singletons nos globals de `app.py` (`# ADR-0093-Phase2-shim: remove after Passo 4`),
  deixando os 105 read-sites intactos. Símbolos de `app.py` acessados via import
  preguiçoso (evita ciclo).
- **Passo 2 (feito):** 6 helpers puros → `api/_decide_helpers.py`
  (`_impact_label`, `_build_bias_declaration`, `sign_verdict`,
  `_appeal_to_response`, `_resolve_domain`, `_resolve_role`). Nenhum lê
  singletons; `sign_verdict` usa `buildtovalue.security.get_hmac_key` (módulo
  externo, não singleton de `app.py`). `_load_slm_config` fica para o Passo 3
  (concern de bootstrap/config; tipá-lo estritamente espalharia `object` no
  construtor do SLM em `_lifespan.py`). `app.py` reimporta os 6 nomes.
- **Passo 3 (em curso):** rotas inline → `api/routes/*` uma a uma (menor→maior
  acoplamento), convertendo os read-sites do router migrado para
  `request.app.state`/`Depends`. Enabler: camada SQLite extraída para
  `api/_db.py` (typed, sem import reverso). Lifespan passa a expor também
  `contestability_loop`, `ethical_engine`, `slm` em `app.state` (aditivo; shim
  intacto). **Router 1 (feito):** `routes/health.py` ← `/health` + `/v1/trust`.
  **Router 2 (feito):** `routes/appeals.py` ← `/v1/appeals/*` (5 rotas), lendo
  `app.state.contestability_loop` via `Depends(get_contestability_loop)`
  fail-secure (503). Acesso direto a `loop.appeals` mantido (atributo público;
  TODO de encapsulamento registrado). Métricas tipadas via `cast` (get_metrics
  devolve `Dict[str, object]`).
  **Router 3 (feito):** `routes/compliance.py` ← `/v1/compliance/*` (8 rotas).
  Decisão de estado: `_risk_classifier` promovido a `app.state.risk_classifier`
  (compartilhado com o hot path `_decide_compliance`; lido via
  `Depends(get_risk_classifier)` — MESMA instância). `COMPLIANCE_PLUGINS`,
  `_fria_generator`, `_ledger_analytics`, `_ropa_generator`, `_art20_generator`,
  `_doc_exporter` → **module-level no router** (compliance-only, sem consumidor
  externo). Rotas ROPA/Art20/Export ganharam modelos Pydantic tipados
  (`ROPARequest`/`Art20Request`/`DocumentExportRequest`) em vez de `req: dict`.
  Guard Fail-Secure (503) se `COMPLIANCE_PLUGINS` vazio.
- **Passo 4:** `routes/decide.py` (`/v1/decide` + `/v1/multi-decide`) por último;
  com todos os readers migrados, **o shim é removido** e os globals deixam de
  existir — `app.py` atinge ~80 linhas.

## Limite inviolável

`rust/kernel/` permanece intocado. A asserção de 9632 bytes de
`TechnicalEvidence` (ADR-063) segue como âncora canônica.
