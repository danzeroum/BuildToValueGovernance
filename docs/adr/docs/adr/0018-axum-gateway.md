# ADR-018: Axum Gateway

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v1.9
**Grupo:** F — API & Observability

## Contexto

O sistema precisa de um HTTP gateway para expor o Rust kernel e orquestrar chamadas ao Python governance. FastAPI serviu como protótipo, mas o gateway definitivo deve ser Rust para manter latência < 50ms p99 end-to-end e evitar serialização inter-processo.

## Decisão

Implementar gateway HTTP em Rust usando Axum (Tokio runtime) como único ponto de entrada HTTP.

### Arquitetura
```
Client → Axum Gateway (:8080)
           ├── POST /v1/validate    → Kernel scan + Policy + HTTP call → Governance (:8000)
           ├── POST /v1/sanitize    → OutputGuard (PII masking)
           ├── POST /v1/policy/test → PolicyEngine test
           ├── GET  /health         → Health check
           └── GET  /metrics        → Prometheus exposition
```

### Crate

- **Nome:** `btv-gateway`
- **Path:** `rust/gateway/`
- **Dependências:** `axum 0.7`, `tokio`, `tower-http` (CORS, trace, timeout), `prometheus`, `reqwest` (HTTP client para governance)

### Responsabilidades

1. Receber request HTTP (JSON)
2. Chamar `buildtovalue-kernel::scan_for_evidence()`
3. Chamar PolicyEngine para hard blocks e policy matching
4. Encaminhar evidence para Python Governance via HTTP (`BTV_GOVERNANCE_URL`)
5. Consolidar resposta (kernel + policy + governance verdict)
6. Registrar métricas Prometheus
7. Append no ledger forensic (decisions.jsonl)
8. Retornar JSON com action, findings, signature, rationale

### Invariantes

- Gateway é stateless (state compartilhado via `Arc<AppState>`)
- Timeout de 5s para chamada ao governance (fail-secure: BLOCK se timeout)
- Todas as rotas retornam JSON (Content-Type: application/json)
- CORS habilitado via tower-http (configurável por env var)
- Sem lógica de negócio no gateway — apenas orquestração

## Fundamento Filosófico

**ADR-009 (Modular Monolith):** O gateway é o único crate novo permitido fora do kernel. Mantém a filosofia de processo único com módulos lógicos separados. Em Docker, gateway e governance são containers separados por necessidade (Rust vs Python), mas conceitualmente operam como monolito modular.

## Consequências

- **Positivas:** Latência observada 6-18ms. Rust-native. Prometheus integrado.
- **Negativas:** Requer `reqwest` para HTTP call ao governance (serialização JSON).
- **Trade-off:** Em produção com FFI (PyO3), a chamada HTTP seria substituída por FFI in-process. Docker atual prioriza simplicidade de deploy.

## Referências

- ADR-009 (Modular Monolith)
- `rust/gateway/src/main.rs`
- `rust/gateway/Cargo.toml`