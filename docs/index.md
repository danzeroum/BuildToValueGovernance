# BuildToValue — Governança Ética para IA

**Proteja seus agentes de IA em 5 minutos. Conformidade com LGPD, EU AI Act e HIPAA sem mudar sua arquitetura.**

---

## O que é o BuildToValue?

O BTV é um gateway de governança que senta entre seus agentes de IA e o mundo. Toda chamada passa por um pipeline de dois estágios:

1. **Kernel Rust** — escaneia PII, injections, e violações de política em <5ms
2. **Judiciário Python** — aplica raciocínio ético (Rawls → Levinas → Jonas → Gilligan) e emite um verdict assinado

O resultado é um `verdict` com ação (`ALLOW`, `BLOCK`, `EDUCATE`, `REDACT`...), rationale filosófico, score de risco, e rastreabilidade completa para auditoria.

```python
from buildtovalue import BTVClient

btv = BTVClient(api_key="...", gateway_url="http://localhost:8080")
verdict = btv.decide("Meu CPF é 123.456.789-09", profile="healthcare")

print(verdict.action)          # "EDUCATE"
print(verdict.explain.summary) # "PII detectado. Misericórdia aplicada: primeira infração."
print(verdict.contestable)     # True
```

---

## Por que o BTV é diferente

| | BTV | Guardrails genéricos | Filtering manual |
|---|---|---|---|
| **PII detection (LGPD)** | ✅ Nativo | ⚠️ Parcial | ❌ Você implementa |
| **Raciocínio ético** | ✅ Rawls/Levinas/Jonas/Gilligan | ❌ | ❌ |
| **Contestabilidade** | ✅ LGPD Art. 20 + EU AI Act Art. 14 | ❌ | ❌ |
| **Trust score por sessão** | ✅ Multi-fatorial | ❌ | ❌ |
| **Verdict assinado (HMAC)** | ✅ Imutável | ❌ | ❌ |
| **Setup** | 5 min | Dias | Semanas |

---

## Comece agora

<div class="grid cards" markdown>

- :material-clock-fast: **Quickstart**

    Instale, configure e faça sua primeira chamada em 5 minutos.

    [→ Quickstart](quickstart.md)

- :material-brain: **Conceitos**

    Entenda a República Algorítmica sem ler os 42 ADRs.

    [→ Conceitos](concepts.md)

- :material-api: **API Reference**

    Documentação completa de todos os endpoints.

    [→ API Reference](api-reference.md)

- :material-puzzle: **Integrações**

    LangChain, LlamaIndex, CrewAI, AutoGen, MCP.

    [→ Integrações](integrations/index.md)

</div>

---

## Playground

Não quer instalar nada? Teste o BTV agora:

[→ Abrir Playground :material-open-in-new:](http://localhost:8502){ .md-button .md-button--primary }

Cole qualquer texto e veja o verdict em tempo real — detecção de PII, análise filosófica, contestabilidade.
