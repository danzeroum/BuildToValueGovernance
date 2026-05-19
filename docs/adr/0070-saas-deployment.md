# ADR-070: SaaS Deployment — Fly.io como Proxy as a Service

**Status:** Aceito  
**Data:** 2026-05-17  
**Autores:** BuildToValue Engineering  
**Relacionados:** ADR-018 (Axum Gateway), ADR-0059 (Rust/Python Boundary), ADR-040 (Gateway v2.0)

---

## Contexto

O Trust OS atingiu maturidade funcional (Fases 1 e 2 concluídas): proxy HTTP transparente operacional, policy bundles curados, suite E2E como contrato do produto. O próximo passo do roadmap (Fase 3 C2) é eliminar a fricção de instalação — de "clone e docker compose" para "aponte `OPENAI_BASE_URL`".

Três opções foram avaliadas para hospedagem gerenciada do Gateway Axum:

---

## Opções Avaliadas

### Opção A — Cloudflare Workers
**Rejeitada.** Workers executam em edge runtime JavaScript/WASM. O binário `btv-gateway` (Rust, Axum, tokio) não pode ser executado diretamente. Migração exigiria: reescrever o gateway em WASM-compatible Rust sem `tokio::main`, sem `std::net`, sem `reqwest` (substituir por `worker-rs` HTTP client). Refatoração estimada: 3-4 semanas, alto risco de regressão nos invariantes criptográficos.

### Opção B — Kubernetes Gerenciado (GKE / EKS)
**Rejeitada para este estágio.** A infra K8s (`ops/k8s/`) já existe e é o path correto para clientes Enterprise on-premise. Para o serviço gerenciado SaaS, K8s exige:
- Gerenciamento contínuo de cluster
- Custo fixo de node pool (mínimo $200/mês em GKE)
- Complexidade operacional incompatível com o estágio atual do produto

### Opção C — Fly.io ✅ (Escolhida)
Fly.io compila diretamente do `Dockerfile.rust` existente, expõe HTTPS automático, escala para zero em idle e tem região `gru` (São Paulo) disponível — requisito de residência de dados para LGPD.

**Vantagens:**
- Zero refatoração de código (apenas `PORT` env var adicionada ao `main.rs`)
- `fly deploy` a partir do `Dockerfile.rust` existente
- Auto-scaling: `min_machines_running = 1`, `auto_stop = true`
- `force_https = true` obrigatório para proxy de tráfego LLM
- Região `gru` mantém dados de cidadãos brasileiros em território nacional (LGPD Art. 44)
- Custo inicial: ~$5/mês (512mb shared CPU)

---

## Decisão

Deploy do `btv-gateway` no Fly.io como serviço gerenciado (`buildtovalue-gateway.fly.dev`).

**Configuração mínima (`fly.toml`):**
- `primary_region = "gru"` (São Paulo)
- `internal_port = 8080` (PORT env var agora configurável via `std::env::var`)
- `force_https = true`
- `min_machines_running = 1` (sem cold-start para clientes Professional/Enterprise)
- Health check: `GET /health` (rota existente em `routes/health.rs`)

**Segredos (fora do fly.toml):**
```bash
fly secrets set BTV_HMAC_KEY=<prod-key>
fly secrets set BTV_API_KEYS=<csv-de-chaves-btv>
fly secrets set BTV_PROXY_UPSTREAM_URL=https://api.openai.com
fly secrets set BTV_GOVERNANCE_URL=https://governance.buildtovalue.io
```

**Sequência de provisionamento:**
```bash
fly launch --dockerfile ops/Dockerfile.rust --no-deploy
fly secrets set BTV_HMAC_KEY=... BTV_API_KEYS=...
fly deploy
```

---

## Invariantes Preservados

- **Fail-secure no proxy:** comportamento inalterado — `PORT` inválida degrada para 8080, nunca pânica em boot
- **LGPD residência de dados:** `primary_region = "gru"` garante processamento em São Paulo
- **K8s path preservado:** `ops/k8s/` permanece funcional para clientes Enterprise on-premise
- **`ops/Dockerfile.rust` inalterado:** Fly.io usa a mesma imagem do quickstart local

---

## Consequências

**Positivas:**
- Onboarding de zero a `OPENAI_BASE_URL=https://buildtovalue-gateway.fly.dev/v1/proxy` em < 5 minutos
- Billing baseado em "decisões governadas" habilitado (Prometheus `/metrics` expõe `btv_proxy_requests_total`)
- HTTPS automático sem necessidade de nginx ou cert-manager

**Negativas / Trade-offs:**
- Dependência de vendor (Fly.io); mitigado pela existência do path K8s como fallback
- Governance service (`BTV_GOVERNANCE_URL`) precisa de deploy separado para o proxy ser funcional em produção
