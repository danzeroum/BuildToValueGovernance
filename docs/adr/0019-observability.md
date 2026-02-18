# ADR-019: Observability (Prometheus + Grafana)

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v1.9
**Grupo:** F — API & Observability

## Contexto

Um sistema de governança ética que opera em tempo real precisa de observabilidade para detectar anomalias, medir SLAs e demonstrar compliance. Sem métricas, não há como provar que o sistema opera dentro dos parâmetros declarados.

## Decisão

Implementar observabilidade via Prometheus (métricas) + Grafana (dashboards) integrados ao Docker Compose.

### Métricas Expostas (Gateway :8080/metrics)

| Métrica | Tipo | Labels | Descrição |
|:---|:---|:---|:---|
| `btv_decisions_total` | Counter | `action` | Decisões por ação (ALLOW/LOG/EDUCATE/REDACT/BLOCK) |
| `btv_mercy_applied_total` | Counter | — | Aplicações de misericórdia (Gilligan) |
| `btv_hard_blocks_total` | Counter | — | Hard blocks (injection, XSS) |
| `btv_latency_ms` | Histogram | — | Latência end-to-end (buckets: 1, 5, 10, 25, 50, 100, 250, 500ms) |
| `btv_findings_total` | Counter | `type` | Findings por tipo (cpf, email, deobfuscator) |
| `btv_sanitize_total` | Counter | — | Requests de sanitização |
| `btv_sanitize_masked_total` | Counter | `type` | PII mascarados por tipo |

### Stack

| Componente | Porta | Função |
|:---|:---|:---|
| Gateway (Rust) | 8080 | Exposição /metrics (Prometheus text format) |
| Prometheus | 9090 | Scraping a cada 5s |
| Grafana | 3000 | Dashboards visuais (admin/btv2026) |

### Invariantes

- Métricas são incrementadas atomicamente (sem race conditions)
- Prometheus scrape interval: 5s (configurável em `ops/prometheus.yml`)
- Latência medida end-to-end (inclui kernel + governance + ledger)
- Nenhuma métrica expõe PII ou dados de sessão

## Fundamento Filosófico

**Jonas (1984):** Responsabilidade proporcional exige transparência sobre o funcionamento do sistema. Métricas são a forma computacional de prestar contas. Sem observabilidade, BiasDeclaration é promessa sem verificação.

## Consequências

- **Positivas:** Visibilidade total sobre comportamento do sistema. Suporta auditoria.
- **Negativas:** Overhead de ~0.5ms por request para atualizar métricas.
- **Futuro:** Distributed tracing (W3C Trace Context) planejado mas não implementado.

## Referências

- ADR-018 (Axum Gateway)
- `ops/docker-compose.yml`
- `ops/prometheus.yml`