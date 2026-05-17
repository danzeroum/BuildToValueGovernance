//! /v1/proxy/*path — Proxy HTTP transparente (Fase 2, ADR-0059).
//!
//! Drop-in para clientes OpenAI/Anthropic/Bedrock: basta apontar
//! OPENAI_BASE_URL=http://btv-gateway:8080/v1/proxy
//!
//! Fluxo:
//!   1. Recebe request do agente (ANY method + path wildcard)
//!   2. Valida contra motor de políticas via governance /v1/validate
//!   3. ALLOW  → encaminha para BTV_PROXY_UPSTREAM_URL/{path}
//!   4. BLOCK  → HTTP 451 com body JSON de evidência (fail-secure)
//!   5. Erro   → HTTP 451 (fail-secure: jamais encaminha em dúvida)
//!
//! Autenticação: ApiKeyLayer (x-api-key BTV) aplica-se a toda a rota.
//! A chave do LLM provider (Authorization: Bearer) é forwarded ao upstream
//! via whitelist de headers — são duas chaves independentes (ADR-0059).

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::json;
use std::sync::Arc;

use crate::state::{AppState, PROXY_BLOCKED_TOTAL, PROXY_FORWARD_LATENCY_MS, PROXY_REQUESTS_TOTAL};
use super::common::governance_url;

/// Headers encaminhados ao upstream — whitelist explícita.
/// Host e Transfer-Encoding são excluídos obrigatoriamente:
///   Host        → reqwest reescreve com o host do upstream
///   Transfer-Encoding → conflito com body já consumido como Bytes
const FORWARD_HEADERS: &[&str] = &[
    "content-type",
    "authorization",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
];

fn upstream_url() -> String {
    std::env::var("BTV_PROXY_UPSTREAM_URL")
        .unwrap_or_else(|_| "https://api.openai.com".to_string())
}

fn filter_forward_headers(incoming: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for name in FORWARD_HEADERS {
        if let Some(val) = incoming.get(*name) {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(val.as_bytes()),
            ) {
                out.insert(n, v);
            }
        }
    }
    out
}

fn block_response(reason: &str) -> Response {
    PROXY_BLOCKED_TOTAL.inc();
    (
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
        Json(json!({
            "blocked": true,
            "verdict": "BLOCK",
            "reason": reason,
            "appeal_url": "/v1/appeals",
        })),
    )
        .into_response()
}

/// ANY /v1/proxy/*path — intercepta, valida e encaminha (ou bloqueia).
pub async fn proxy_forward(
    State(state): State<Arc<AppState>>,
    method: Method,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    PROXY_REQUESTS_TOTAL.inc();
    let _timer = PROXY_FORWARD_LATENCY_MS.start_timer();

    // Valida o body contra o motor de políticas.
    // Fail-secure: qualquer erro (timeout, parse, governance down) → BLOCK.
    let validate_payload = json!({
        "input": String::from_utf8_lossy(&body),
        "session_id": "proxy-intercept",
        "method": method.as_str(),
        "path": path,
    });

    let governance_result = state
        .http_client
        .post(format!("{}/v1/validate", governance_url()))
        .json(&validate_payload)
        .send()
        .await;

    let verdict = match governance_result {
        Err(_) => {
            return block_response("Governance unavailable — fail-secure block");
        }
        Ok(resp) => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            body.get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("BLOCK")
                .to_string()
        }
    };

    if verdict != "ALLOW" {
        return block_response("Policy violation detected by BTV Trust OS");
    }

    // Encaminha para o upstream.
    let forward_url = format!("{}/{}", upstream_url().trim_end_matches('/'), path);
    let upstream = state
        .http_client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes())
                .unwrap_or(reqwest::Method::POST),
            &forward_url,
        )
        .headers(filter_forward_headers(&headers))
        .body(body.to_vec())
        .send()
        .await;

    match upstream {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let upstream_body = resp.bytes().await.unwrap_or_default();
            (status, upstream_body).into_response()
        }
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
