# ADR-0095: Decomposição de `contestability_loop.py` em subpacote

**Status**: ✅ ACEITO (implementado)
**Data**: 29 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `python/buildtovalue/governance/contestability/` (novo subpacote);
             `contestability_loop.py` vira facade de compatibilidade.
**Pré-requisitos**: nenhum (refatoração interna, zero mudança de comportamento).

---

## Contexto

`governance/contestability_loop.py` (22,0 KB) misturava tipos de verdict
(`EthicalVerdict` + `build_verdict`), tipos de recurso (`AppealStatus`,
`Appeal`), vocabulários controlados de grounds e a classe `ContestabilityLoop`
(orquestração do loop de apelações + SLA + persistência SQLite).

## Decisão

Extrair para o subpacote `contestability/`:

- `_types.py` — `VALID_GROUNDS`, `VALID_MEDIATOR_RECOMMENDATIONS`,
  `EthicalVerdict` (+ `build_verdict` e helpers), `AppealStatus`, `Appeal`.
  `Appeal.is_overdue` é a fonte do predicado de SLA 24h.
- `_loop.py` — a classe `ContestabilityLoop`. Depende de `_types`.
- `__init__.py` — reexporta a API pública.

`contestability_loop.py` passa a ser **facade** com `__all__` explícito.
**Critério de aceite**: `from buildtovalue.governance.contestability_loop
import ContestabilityLoop, Appeal, AppealStatus` (e demais símbolos públicos)
continua funcionando. `contestability_escalation.py` permanece como **módulo
irmão** (importa da facade), não migrado — preserva sua testabilidade
independente e evita acoplamento de subpacote.

## Desvio documentado (SLA)

O plano previa um `_sla.py` isolado. Na prática, a lógica de SLA é
inseparável do loop: o **predicado** de prazo vive em `Appeal.is_overdue`
(`_types`), enquanto a **varredura/expiração** (`list_expired_appeals`,
`expire_overdue`, `get_sla_compliance_rate`) são métodos de
`ContestabilityLoop` que dependem do estado da classe. Extraí-los exigiria
fraturar a classe — risco em lógica que sustenta o direito de contestação.
Mantém-se coeso em `_loop.py`, com o prazo de 24h em um único lugar (`Appeal`).

## Invariantes preservadas (Gilligan/Jonas)

- SLA 24h soberano: `Appeal.__post_init__` fixa `sla_deadline = timestamp + 24h`.
- Persistência durável (SQLite via `sqlite_connect_wal`) sobrevive a restart.
- `mediator_recommendation` inválido é ignorado com log — nunca aplica delta
  de trust indevido (Gilligan: `educate` não penaliza).

## Consequências

- Zero mudança de comportamento; testes de appeals/contestabilidade passam.
- `mypy --strict` limpo nos 2 novos módulos (zero `Any`; `trust_store` agora
  é um `Protocol` tipado em vez de `object`).
