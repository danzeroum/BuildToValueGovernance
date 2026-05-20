[BuildToValue](../../README.md) › [Documentação](../README.md) › [Trilha Engenheiro](../for-engineers.md) › [Integrações](./index.md) › **Python SDK**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb)

<!-- audience: engineer -->

---

# Python SDK

```bash
pip install buildtovalue
```

Suporta Python 3.10+. Clientes síncrono e assíncrono. Retry automático com backoff.

---

## Clientes disponíveis

| Cliente | Quando usar |
|---|---|
| `BTVClient` | Apps síncronas, scripts, Flask, Django |
| `AsyncBTVClient` | FastAPI, asyncio, async frameworks |
| `BTVSession` | Múltiplas chamadas com o mesmo `session_id` |

---

## BTVClient (síncrono)

```python
from buildtovalue import BTVClient

with BTVClient(
    api_key="...",
    gateway_url="http://localhost:8080",
    timeout=30.0,        # segundos
    max_retries=3,       # retry em 503/429/502
    raise_on_block=False # True → lança BTVBlockedError
) as btv:

    # Pipeline ético completo
    verdict = btv.decide("texto", session_id="sess-001", profile="healthcare")

    # Scan rápido (Rust only)
    v = btv.validate("texto", session_id="sess-001")

    # Mascarar PII
    result = btv.sanitize("Meu CPF é 123.456.789-09")
    print(result.sanitized)  # "Meu CPF é [CPF]"

    # Appeal
    appeal = btv.appeal(
        verdict.verdict_id,
        reason="Dado de teste ABNT — não é PII real.",
        grounds=["technical_error"],
    )

    # Trust score
    ts = btv.trust_score("sess-001")
    print(ts.level)  # "high" | "medium" | "low"

    # Health (sem auth)
    print(btv.health())
```

---

## AsyncBTVClient

```python
import asyncio
from buildtovalue import AsyncBTVClient

async def main():
    async with AsyncBTVClient(api_key="...", gateway_url="http://localhost:8080") as btv:
        verdict = await btv.decide("texto", session_id="sess-001")
        print(verdict.action)

asyncio.run(main())
```

---

## BTVSession — context manager de sessão

Evita repetir `session_id` em cada chamada:

```python
with btv.session("sess-user-001") as s:
    v1 = s.decide("Hello")
    v2 = s.validate("SELECT * FROM users")
    ts = s.trust_score()

# Versão async
async with btv_async.session("sess-001") as s:
    v = await s.decide("texto")
```

---

## Modelos de resposta

```python
from buildtovalue.models import (
    Verdict,        # resposta de /v1/decide
    ValidateVerdict, # resposta de /v1/validate
    Appeal,         # resposta de /v1/appeals
    TrustScore,     # resposta de /v1/trust/{id}
    SanitizeResult, # resposta de /v1/sanitize
)
from buildtovalue.models import VerdictAction, AppealStatus, AppealGrounds
```

### Verdict

```python
verdict.verdict_id          # "VRD-01ARZ3NDEK..."
verdict.action              # VerdictAction.ALLOW | BLOCK | EDUCATE | ...
verdict.original_action     # antes da misericórdia
verdict.mercy_applied       # bool
verdict.composite_risk      # float [0.0, 1.0]
verdict.finding_count       # int
verdict.critical_count      # int
verdict.hard_blocked        # bool
verdict.contestable         # bool
verdict.appeal_deadline_hours # int
verdict.signature           # HMAC-SHA256

# Propriedades calculadas
verdict.is_blocked  # bool
verdict.is_allowed  # bool
verdict.explanation # rationale + explain.summary

# Rationale filosófico
verdict.explain.summary
verdict.explain.rawls_rationale
verdict.explain.levinas_rationale
verdict.explain.jonas_rationale
verdict.explain.gilligan_rationale
verdict.explain.trust_score   # float
verdict.explain.mercy_score   # float
```

---

## Tratamento de erros

```python
from buildtovalue.exceptions import (
    BTVError,          # base
    BTVAuthError,      # 401 — API key inválida
    BTVBlockedError,   # action==BLOCK quando raise_on_block=True
    BTVRateLimitError, # 429 — .retry_after em segundos
    BTVGatewayError,   # 5xx
    BTVValidationError # 4xx
)

try:
    verdict = btv.decide("texto")
except BTVAuthError:
    print("API key inválida")
except BTVRateLimitError as e:
    print(f"Rate limit — tente novamente em {e.retry_after}s")
except BTVGatewayError as e:
    print(f"Gateway error {e.status_code}")
```

---

## raise_on_block

```python
btv = BTVClient(api_key="...", raise_on_block=True)

try:
    verdict = btv.decide("DROP TABLE users")
except BTVBlockedError as e:
    print(e.verdict.verdict_id)  # acesso ao verdict completo
    print(e.verdict.contestable)
```

---

## Retry automático

O SDK faz retry automático em `429`, `500`, `502`, `503`, `504` com backoff exponencial:

- Attempt 1: imediato
- Attempt 2: 2s
- Attempt 3: 4s
- Attempt 4: 8s

Em 429, respeita o header `Retry-After` do servidor.

---

### Próximos passos / Relacionados

- [Integrações — visão geral](./index.md)
- [API Reference](../api-reference.md)
- [Conceitos](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Trilha Engenheiro](../for-engineers.md) · [Trilha DPO/CISO](../for-dpo-ciso.md) · [Links de Referência](../reference-links.md)</sub>
