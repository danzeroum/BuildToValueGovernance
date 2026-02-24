# ADR-040: Axum Gateway v2.0 — Extensões para República Algorítmica Completa

**Status:** 🆕 PROPOSTO
**Data:** 24 de fevereiro de 2026
**Autores:** IA Arquiteta (Claude Sonnet 4.6) — validado por Staff Engineer
**Versão alvo:** v1.9.0 (extensão do gateway existente)
**Grupo:** F — API & Observability
**Estende:** ADR-018 (Axum Gateway v1.9 — ativo)
**Depende de:** ADR-032 (ScanContextFlags), ADR-036 (Bias Guardian), ADR-037 (AppealEngine), ADR-039 (TrustScoreCalculator)

**Impacto:**
```
rust/gateway/src/routes/mod.rs          — + 3 novas rotas
rust/gateway/src/routes/appeals.rs      — novo (proxy AppealEngine)
rust/gateway/src/routes/health_bias.rs  — novo (/health/bias)
rust/gateway/src/routes/decide.rs       — novo (/v1/decide — alias semântico)
rust/gateway/src/middleware/rate_limit.rs — extensão: per-tenant
rust/gateway/src/state.rs               — + tenant_registry
```

---

## 1. Contexto

### 1.1 O que o gateway atual não cobre

O gateway v1.9 (`ADR-018`) está operacional com `/v1/validate`, `/v1/sanitize`, `/health`, `/metrics`. Os ADRs 037–039 criam contratos novos que o gateway precisa expor:

| Contrato novo | ADR | Gap no gateway |
|:---|:---:|:---|
| `POST /v1/appeals` + `GET /v1/appeals/{id}` + `POST /v1/appeals/{id}/resolve` | 037 | Ausente — AppealEngine só exposto via Python `:8000` |
| `GET /health/bias` | 036 | Ausente — BiasGuardian sem endpoint de monitoramento |
| `POST /v1/decide` | 038 | `/v1/validate` existe mas semântica é `scan`; `decide` é `scan + ética` |
| Rate limiting por `tenant_key` | 032 | Rate limit atual é per-IP; multi-tenant exige per-tenant |
| `X-BTV-Jurisdiction` → `jurisdiction_bitmask` | 035 | Header não é lido nem injetado no `ScanContext` |

### 1.2 O que NÃO muda

A arquitetura core do ADR-018 é preservada: `Arc<AppState>` stateless, `reqwest` para proxy ao Python governance, `tower-http` para CORS/timeout/trace, Prometheus em `/metrics`. Este ADR **adiciona** sem quebrar.

---

## 2. Decisão

### 2.1 Mapa de Rotas v2.0

```
Client → Axum Gateway (:8080)
  ├── POST /v1/validate          → [existente] kernel + policy + governance
  ├── POST /v1/decide            → [NOVO] alias semântico de /v1/validate
  │                                  + injeta X-BTV-Pipeline-Stage: ethical
  ├── POST /v1/sanitize          → [existente]
  ├── POST /v1/policy/test       → [existente]
  ├── POST /v1/guard             → [existente]
  │
  ├── POST   /v1/appeals         → [NOVO] proxy → Python :8000/v1/appeals
  ├── GET    /v1/appeals/{id}    → [NOVO] proxy → Python :8000/v1/appeals/{id}
  ├── POST   /v1/appeals/{id}/resolve → [NOVO] proxy
  ├── GET    /v1/appeals/metrics → [NOVO] proxy
  │
  ├── GET  /health               → [existente]
  ├── GET  /health/bias          → [NOVO] BiasGuardian status
  ├── GET  /metrics              → [existente] Prometheus
  └── GET  /v1/trust/{session}   → [NOVO] proxy → Python :8000/v1/trust/{session}
```

### 2.2 Rota `/v1/decide` — Alias Semântico

```rust
// rust/gateway/src/routes/decide.rs

//! POST /v1/decide — Pipeline ético completo (ADR-038).
//!
//! Diferença vs /v1/validate:
//!   - Injeta header X-BTV-Pipeline-Stage: ethical no request ao governance
//!   - Extrai X-BTV-Jurisdiction para preencher jurisdiction_bitmask
//!   - Retorna ExplainDecision estruturado (não apenas rationale string)
//!
//! /v1/validate permanece para compatibilidade retroativa.
//! Novos clientes devem usar /v1/decide.

use axum::{extract::State, http::{HeaderMap, StatusCode}, Json};
use std::sync::Arc;
use crate::state::AppState;
use crate::routes::validate::{ValidateRequest, ValidateResponse, run_scan};

#[derive(serde::Deserialize)]
pub struct DecideRequest {
    pub input: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,   // NOVO: para ExplainDecision
    #[serde(default)]
    pub domain: Option<String>,     // NOVO: para LevinasStage
    #[serde(default)]
    pub user_role: Option<String>,  // NOVO: para GilliganStage
}

pub async fn decide_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DecideRequest>,
) -> Result<Json<ValidateResponse>, StatusCode> {
    // Extrai jurisdiction do header X-BTV-Jurisdiction
    // Valor: "BR" | "US" | "EU" | "UK" | combinação "BR,EU"
    let jurisdiction_bitmask: u64 = headers
        .get("X-BTV-Jurisdiction")
        .and_then(|v| v.to_str().ok())
        .map(parse_jurisdiction_bitmask)
        .unwrap_or(0x01);  // default: BR (bit 0)

    // Reconstrói como ValidateRequest com metadados extras no profile
    let validate_req = ValidateRequest {
        input: req.input,
        session_id: req.session_id,
        profile: req.profile,
        // jurisdiction_bitmask injetado no GovernanceRequest via campo extra
    };

    // Delega ao handler de validate com flag ethical=true
    run_scan(state, validate_req, Some(jurisdiction_bitmask), true).await
}

fn parse_jurisdiction_bitmask(header: &str) -> u64 {
    let mut mask: u64 = 0;
    for part in header.split(',') {
        match part.trim() {
            "BR" => mask |= 0x01,
            "US" => mask |= 0x02,
            "EU" => mask |= 0x04,
            "UK" => mask |= 0x08,
            _    => {}
        }
    }
    if mask == 0 { 0x01 } else { mask }  // fallback: BR
}
```

### 2.3 Rota `/v1/appeals` — Proxy Transparente

```rust
// rust/gateway/src/routes/appeals.rs

//! Proxy transparente para AppealEngine (Python :8000).
//!
//! Filosofia (Levinas): o gateway não filtra nem modifica appeals.
//! Sua responsabilidade é rotear com fidelidade e fail-secure.
//!
//! Fail-secure: qualquer erro de proxy → 503 com body estruturado.
//! NUNCA retornar silently 200 em caso de falha.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::state::AppState;

const APPEALS_PROXY_TIMEOUT_MS: u64 = 10_000;  // 10s — humano pode demorar mais

async fn proxy_to_governance(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Json<Value>, StatusCode> {
    let governance_url = std::env::var("BTV_GOVERNANCE_URL")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());

    let url = format!("{}{}", governance_url, path);
    let client = &state.http_client;

    let mut req = client.request(method, &url)
        .timeout(std::time::Duration::from_millis(APPEALS_PROXY_TIMEOUT_MS));

    if let Some(b) = body {
        req = req.json(&b);
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let body: Value = resp.json().await
                .unwrap_or_else(|_| json!({"error": "invalid_json"}));

            // Preserva status codes do governance (201, 400, 404, 409)
            match status.as_u16() {
                200 | 201 => Ok(Json(body)),
                400 => Err(StatusCode::BAD_REQUEST),
                404 => Err(StatusCode::NOT_FOUND),
                409 => Err(StatusCode::CONFLICT),
                _   => Err(StatusCode::BAD_GATEWAY),
            }
        }
        // Fail-secure: qualquer falha de rede → 503
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

pub async fn submit_appeal(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    proxy_to_governance(&state, reqwest::Method::POST, "/v1/appeals", Some(body)).await
}

pub async fn get_appeal(
    State(state): State<Arc<AppState>>,
    Path(appeal_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    proxy_to_governance(
        &state, reqwest::Method::GET,
        &format!("/v1/appeals/{}", appeal_id),
        None,
    ).await
}

pub async fn resolve_appeal(
    State(state): State<Arc<AppState>>,
    Path(appeal_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    proxy_to_governance(
        &state, reqwest::Method::POST,
        &format!("/v1/appeals/{}/resolve", appeal_id),
        Some(body),
    ).await
}

pub async fn appeals_metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, StatusCode> {
    proxy_to_governance(&state, reqwest::Method::GET, "/v1/appeals/metrics", None).await
}
```

### 2.4 Rota `/health/bias` — BiasGuardian Status

```rust
// rust/gateway/src/routes/health_bias.rs

//! GET /health/bias — Estado atual do BiasGuardian (ADR-036).
//!
//! Retorna o resultado mais recente dos relatórios RT-XXX.
//! Permite monitoramento contínuo de divergência BiasDeclaration.
//!
//! Jonas: responsabilidade pública sobre limitações do sistema.

use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::state::AppState;

pub async fn health_bias_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    let governance_url = std::env::var("BTV_GOVERNANCE_URL")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());

    // Consulta BiasGuardian via Python governance
    match state.http_client
        .get(format!("{}/health/bias", governance_url))
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: Value = resp.json().await
                .unwrap_or_else(|_| json!({"status": "parse_error"}));
            Json(body)
        }
        // Fail-secure: sem dados → declarar status desconhecido, não OK
        _ => Json(json!({
            "status": "unknown",
            "reason": "governance_unreachable",
            "bias_divergence_ok": false,
            "note": "BiasGuardian status indisponível — tratar como WARNING (Jonas)"
        })),
    }
}
```

Endpoint Python correspondente (adição em `app.py`):

```python
# python/buildtovalue/api/app.py — novo endpoint

from buildtovalue.governance.bias_guardian import BiasGuardian, DivergenceLevel
from pathlib import Path

_bias_guardian = BiasGuardian(Path("ops/red-team/reports"))

@app.get("/health/bias")
def health_bias():
    result = _bias_guardian.evaluate_suite()
    return {
        "status": result.overall_level.value,
        "bias_divergence_ok": result.overall_level == DivergenceLevel.OK,
        "blocking_modules": result.blocking_modules,
        "warning_modules": result.warning_modules,
        "run_id": result.run_id,
        "timestamp": result.timestamp,
        "explain": result.explain_decision(),
    }
```

### 2.5 Rate Limiting por Tenant (extensão do middleware existente)

```rust
// rust/gateway/src/middleware/rate_limit.rs — extensão

//! Extensão v2.0: rate limit per-tenant via X-BTV-Tenant-Key header.
//!
//! v1.9: per-IP (100 req/min)
//! v2.0: per-tenant override se header presente
//!
//! Rawls: mesmos thresholds para todos os tenants do mesmo tier.
//! Jonas: tenant desconhecido recebe limite mais restritivo (fail-safe).

/// Configuração por tier de tenant
pub struct TenantTierConfig {
    pub free_tier_rpm: u32,      // 60  req/min
    pub standard_tier_rpm: u32,  // 300 req/min
    pub enterprise_tier_rpm: u32,// 1000 req/min
}

impl Default for TenantTierConfig {
    fn default() -> Self {
        Self {
            free_tier_rpm: std::env::var("BTV_RL_FREE_RPM")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(60),
            standard_tier_rpm: std::env::var("BTV_RL_STANDARD_RPM")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(300),
            enterprise_tier_rpm: std::env::var("BTV_RL_ENTERPRISE_RPM")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(1000),
        }
    }
}

/// Extrai chave de rate limit: preferencialmente tenant_key, fallback IP.
/// tenant_key = BLAKE3(X-BTV-Tenant-Key header)[0..16] — nunca armazena em claro.
fn extract_rate_limit_key(req: &Request<Body>) -> String {
    if let Some(tenant_header) = req.headers().get("X-BTV-Tenant-Key") {
        if let Ok(tenant_str) = tenant_header.to_str() {
            // Hash do tenant key — nunca armazenar o valor original
            let hash = blake3::hash(tenant_str.as_bytes());
            return format!("tenant:{}", &hash.to_hex()[..16]);
        }
    }
    // Fallback: per-IP (comportamento v1.9)
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|ip| format!("ip:{}", ip.split(',').next().unwrap_or("unknown")))
        .unwrap_or_else(|| "ip:unknown".to_string())
}
```

### 2.6 Atualização de `routes/mod.rs`

```rust
// rust/gateway/src/routes/mod.rs — v2.0

pub mod validate;
pub mod decide;      // NOVO
pub mod appeals;     // NOVO
pub mod health_bias; // NOVO
pub mod health;
pub mod metrics;
pub mod blind_review;
pub mod sanitize;
pub mod guard;
pub mod trust;       // NOVO (proxy /v1/trust/{session})

use std::sync::Arc;
use axum::{Router, routing::{get, post}};
// ... imports existentes preservados ...
use crate::state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    // ... configuração existente de CORS, layers ...

    Router::new()
        // ── Rotas existentes (inalteradas) ────────────────────
        .route("/v1/validate",       post(validate::validate_handler))
        .route("/v1/sanitize",       post(sanitize::sanitize_handler))
        .route("/v1/policy/test",    post(blind_review::policy_test_handler))
        .route("/v1/guard",          post(guard::guard_handler))
        .route("/health",            get(health::health_handler))
        .route("/metrics",           get(metrics::metrics_handler))

        // ── Novas rotas v2.0 ──────────────────────────────────
        .route("/v1/decide",         post(decide::decide_handler))

        // Appeals proxy (ADR-037)
        .route("/v1/appeals",        post(appeals::submit_appeal))
        .route("/v1/appeals/metrics",get(appeals::appeals_metrics))
        .route("/v1/appeals/:id",    get(appeals::get_appeal))
        .route("/v1/appeals/:id/resolve", post(appeals::resolve_appeal))

        // BiasGuardian health (ADR-036)
        .route("/health/bias",       get(health_bias::health_bias_handler))

        // Trust score (ADR-039)
        .route("/v1/trust/:session", get(trust::get_trust_handler))

        // ── Layers (ordem preservada) ─────────────────────────
        .layer(ApiKeyLayer::from_env())
        .layer(RateLimitLayer::from_env())
        .layer(middleware::from_fn(trace_propagation))
        .layer(cors)
        .layer(TimeoutLayer::new(Duration::from_secs(20)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
```

### 2.7 Novas Métricas Prometheus (adição em `state.rs`)

```rust
// Adições em rust/gateway/src/state.rs — lazy_static!

pub static ref APPEALS_SUBMITTED_TOTAL: IntCounter = register_int_counter!(
    "btv_appeals_submitted_total", "Total de appeals submetidos"
).unwrap();

pub static ref APPEALS_PROXY_ERRORS_TOTAL: IntCounter = register_int_counter!(
    "btv_appeals_proxy_errors_total", "Falhas no proxy para AppealEngine"
).unwrap();

pub static ref BIAS_DIVERGENCE_BLOCKS_TOTAL: IntCounter = register_int_counter!(
    "btv_bias_divergence_blocks_total", "BiasDeclarations bloqueadas pelo Bias Guardian"
).unwrap();

pub static ref TENANT_RATE_LIMITED_TOTAL: IntCounterVec = register_int_counter_vec!(
    opts!("btv_tenant_rate_limited_total", "Rate limits por tenant tier"),
    &["tier"]
).unwrap();
```

---

## 3. Invariantes do Gateway v2.0

| Invariante | Valor | Justificativa |
|:---|:---|:---|
| Timeout appeals proxy | 10s | Humanos podem demorar; 5s era insuficiente |
| Timeout governance `/v1/decide` | 5s | Mantém SLA < 50ms p99 para decisão ética |
| Timeout `/health/bias` | 3s | Health check deve ser rápido |
| Fallback `/health/bias` | `bias_divergence_ok: false` | Fail-secure: sem dados = aviso, não OK |
| `X-BTV-Tenant-Key` armazenado | Nunca em claro | BLAKE3 hash 16 bytes (ADR-032) |
| Rotas de appeals | Proxy puro | Sem lógica de negócio no gateway (ADR-018) |

---

## 4. Fundamentos Filosóficos

**Levinas (Proxy sem filtro para appeals):** o gateway não pode censurar ou modificar uma contestação. Seu papel é roteamento fiel — qualquer filtragem seria violação do direito de recurso.

**Jonas (`/health/bias` fail-secure):** quando o BiasGuardian está inacessível, o gateway declara `bias_divergence_ok: false` em vez de `true`. Não conhecer o estado das limitações do sistema é pior do que declará-las conservadoramente.

**Rawls (Rate limit por tier):** os thresholds por tier (free/standard/enterprise) são configurados via env vars e aplicados cegamente — o mesmo threshold para todos os tenants do mesmo tier, sem exceções individuais.

---

## 5. Consequências

### Positivas

O gateway passa a ser o único ponto de entrada para toda a República Algorítmica — incluindo appeals e monitoramento de bias. Clientes externos integram uma única URL (`:8080`) e recebem o sistema completo. `/v1/decide` estabelece semântica clara: não é um simples scan, é uma decisão ética com pipeline filosófico.

### Negativas e Trade-offs

O proxy de appeals adiciona um hop de latência (gateway → Python) para operações que já são lentas por natureza (human-in-the-loop). Para appeals isso é aceitável; para `/v1/decide` não é — por isso o timeout permanece 5s com fail-secure.

A rota `/v1/trust/:session` expõe trust scores via gateway. Isso requer que o `session_id` nunca seja o `user_id` real — invariante já garantida pelo `TrustScoreCalculator` (ADR-039, privacy-preserving).

---

## 6. Testes Obrigatórios

```
[ ] POST /v1/decide → resposta com action + explain (não apenas rationale)
[ ] POST /v1/decide com X-BTV-Jurisdiction: EU → jurisdiction_bitmask = 0x04
[ ] POST /v1/decide com X-BTV-Jurisdiction: BR,UK → bitmask = 0x09
[ ] POST /v1/appeals → proxy 201 do governance
[ ] POST /v1/appeals (governance down) → 503 (fail-secure, não 500 genérico)
[ ] GET /v1/appeals/{id} → proxy 200 ou 404
[ ] POST /v1/appeals/{id}/resolve → proxy 200 ou 409
[ ] GET /health/bias (governance ok) → body com bias_divergence_ok
[ ] GET /health/bias (governance down) → bias_divergence_ok: false
[ ] Rate limit per-tenant: mesmo tenant → contagem compartilhada
[ ] Rate limit per-tenant: tenants diferentes → contagens independentes
[ ] X-BTV-Tenant-Key nunca aparece em logs (BLAKE3 hash apenas)
[ ] /v1/validate continua funcionando (retrocompat)
[ ] Todas as rotas novas registram métricas Prometheus
```
