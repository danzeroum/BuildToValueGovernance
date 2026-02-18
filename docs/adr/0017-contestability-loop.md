# ADR-017: Contestability Loop (SLA 24h)

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v1.8
**Grupo:** E — Governance

## Contexto

O sistema declara `contestable: true` e `appeal_deadline_hours: 24` em todo EthicalVerdict (ADR-016). Contudo, sem endpoints HTTP para submeter, consultar e resolver appeals, a promessa de contestabilidade é vazia. LGPD Art. 20 e EU AI Act Art. 14 exigem mecanismos reais de recurso humano.

## Decisão

Implementar ContestabilityLoop como serviço Python com persistência SQLite e exposição via API REST.

### Fluxo
```
Usuário recebe BLOCK com verdict_id
  → POST /v1/appeals/submit {verdict_id, reason}
  → Appeal criado (status: PENDING, SLA: now + 24h)
  → Humano revisa via GET /v1/appeals/pending
  → POST /v1/appeals/{id}/resolve {accepted: bool, notes}
  → Se accepted: trust score incrementado, decisão revertida no ledger
  → Se rejected: notas de justificativa registradas
  → Métricas: SLA compliance rate, appeal success rate
```

### Endpoints

| Método | Path | Função |
|:---|:---|:---|
| POST | `/v1/appeals/submit` | Submeter appeal |
| GET | `/v1/appeals/{id}` | Status do appeal |
| GET | `/v1/appeals/pending` | Listar pendentes |
| POST | `/v1/appeals/{id}/resolve` | Resolver (humano) |
| GET | `/v1/appeals/metrics` | SLA compliance |

### Invariantes

- Todo appeal gera entrada no ledger (auditoria)
- SLA 24h: appeals não resolvidos em 24h mudam para EXPIRED
- Appeals aceitos incrementam trust score em +0.1
- Hard blocks (SQL injection, XSS) NÃO são contestáveis
- Máximo 3 appeals por verdict_id (anti-abuse)

## Fundamento Filosófico

**Levinas (1961):** O dever de cuidado exige que toda decisão automatizada possa ser contestada por um humano. A responsabilidade não termina na execução — estende-se até a possibilidade de reversão.

**LGPD Art. 20:** "O titular dos dados tem direito a solicitar a revisão de decisões tomadas unicamente com base em tratamento automatizado."

## Consequências

- **Positivas:** Compliance real com LGPD/EU AI Act. Feedback loop melhora sistema.
- **Negativas:** Requer humano para resolver. Em escala, precisa de fila e SLA monitoring.
- **Risco:** SLA de 24h é aspiracional. Em produção, depende de staffing do Ethical Committee.

## Referências

- ADR-016 (EthicalContextEngine v4)
- ADR-004 (Immutable Ledger)
- `python/buildtovalue/governance/contestability_loop.py` (implementação existente)