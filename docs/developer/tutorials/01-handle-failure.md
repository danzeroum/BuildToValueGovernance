---
title: "Tutorial 01 — Tratando o Bloqueio (Fail-Secure)"
---

# Tutorial 01 — Tratando o Bloqueio

> Este é o **primeiro** tutorial intencionalmente. No BTV, o bloqueio é onde a
> confiança é testada — não o caminho feliz.

## Objetivo

Você vai:

1. Disparar um cenário que produz `HTTP 451`.
2. Ler a evidência associada ao bloqueio.
3. Apresentar o `ContestabilityLoop` ao usuário final.

## Pré-requisitos

- Emulador local rodando: `make emulator-up`.
- `curl` ou seu HTTP client favorito.

## Passo 1 — Disparar o bloqueio

```bash
curl -i -X POST http://localhost:8080/v1/decide \
  -H 'Content-Type: application/json' \
  -d @demo/playground/scenarios/block-451.json
```

Resposta esperada:

```http
HTTP/1.1 451 Unavailable For Legal Reasons
Content-Type: application/json
X-BTV-Evidence-Hash: <hash hex>

{
  "decision": "BLOCK",
  "reason": "policy_violation:HIPAA_base",
  "evidence_url": "/v1/evidence/<hash>",
  "contestability": {
    "endpoint": "/v1/contest",
    "sla_hours": 24,
    "protocol": "ADR-0047"
  }
}
```

## Passo 2 — Ler a evidência

```bash
curl http://localhost:8080/v1/evidence/<hash> | jq .
```

O tamanho do payload deve bater com o **tamanho constitucional**
(ver [referência técnica gerada](../reference/index.md)).

## Passo 3 — Apresentar a contestação

Não capture o `451` silenciosamente. Apresente ao usuário final:

- A razão estruturada (`reason`).
- O link para abrir contestação (`contestability.endpoint`).
- O SLA (`contestability.sla_hours`).

O playground faz isso por você — veja
[`demo/playground/index.html`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/demo/playground/index.html).

## O que você aprendeu

- O BTV falha fechado por design ([fail-secure](../concepts/fail-secure.md)).
- Toda decisão produz evidência auditável ([anatomia](../concepts/evidence-anatomy.md)).
- Todo bloqueio admite contestação ([loop](../concepts/contestability-loop.md)).

## Próximo passo

- **Trilha do Integrador:** [Tutorial 02 — Primeira Integração](02-first-integration.md).
- **Quer auditar a prova fora do navegador?** [Tutorial 03 — `btv-cli verify`](03-verify-evidence-cli.md).
