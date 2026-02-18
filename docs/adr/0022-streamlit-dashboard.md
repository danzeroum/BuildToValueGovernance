# ADR-022: Streamlit Dashboard MVP

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v2.0
**Grupo:** G — Intelligence & Compliance

## Contexto

O sistema opera exclusivamente via API (curl/código). Para demonstração, auditoria visual e onboarding de stakeholders não-técnicos, precisa de uma interface gráfica. A escolha é entre Streamlit (rápido, Python, MVP) e Angular (enterprise, complexo, futuro).

## Decisão

Implementar dashboard MVP em Streamlit. Angular reservado para versão Enterprise pós-v2.0.

### Pages

| Page | Função | Backend |
|:---|:---|:---|
| **Validate** | Input scan + verdict visual | Gateway :8080 |
| **Sanitize** | PII masking visual | Gateway :8080 |
| **Trust Score** | Lookup de confiança por sessão | Governance :8000 |
| **Compliance** | Relatórios LGPD / EU AI Act | Governance :8000 |
| **Intelligence** | Browse + ingest threats | Governance :8000 |
| **Metrics** | Health + Prometheus raw | Gateway + Governance |

### Arquitetura
```
Browser → Streamlit (:8501)
             ├── requests.post(GATEWAY_URL/v1/validate)
             ├── requests.post(GATEWAY_URL/v1/sanitize)
             ├── requests.get(GOVERNANCE_URL/v1/trust/{id})
             ├── requests.get(GOVERNANCE_URL/v1/compliance/report/{fw})
             ├── requests.post(GOVERNANCE_URL/v1/intelligence/query)
             └── requests.get(GATEWAY_URL/metrics)
```

### Invariantes

- Dashboard é read-only + validate/ingest (sem admin operations)
- URLs configuráveis via env var (`BTV_GATEWAY_URL`, `BTV_GOVERNANCE_URL`)
- Docker container separado (`ops/Dockerfile.streamlit`)
- Sem autenticação (MVP). Auth planejada para versão Enterprise.

## Fundamento Filosófico

**Rawls (1971):** Transparência radical requer que o funcionamento do sistema seja visível a todos os stakeholders, não apenas a desenvolvedores com acesso ao terminal. O dashboard democratiza o acesso à informação de governança.

## Consequências

- **Positivas:** Demonstração visual para stakeholders. Onboarding em <5min.
- **Negativas:** Streamlit não escala para multi-tenant. Sem auth. Sem customização avançada.
- **Futuro:** Angular Enterprise Dashboard substituirá Streamlit quando multi-tenant for necessário.

## Referências

- `python/buildtovalue/dashboard/app.py`
- `ops/Dockerfile.streamlit`
- `ops/docker-compose.yml`