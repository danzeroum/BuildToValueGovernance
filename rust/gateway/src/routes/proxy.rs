//! /v1/proxy/*path — Proxy HTTP transparente (Fase 2, ADR-0059).
//!
//! Drop-in para clientes OpenAI/Anthropic/Bedrock: basta apontar
//! OPENAI_BASE_URL=http://btv-gateway:8080/v1/proxy
//!
//! Fluxo:
//!   1. Recebe request do agente (ANY method + path wildcard)
//!   2. Kernel scan (gatekeeper) + policy evaluation (Rust, síncrono)
//!   3. Governance /v1/decide (Python, assíncrono)
//!   4. ALLOW  → encaminha para BTV_PROXY_UPSTREAM_URL/{path}
//!   5. BLOCK  → HTTP 451 com body JSON de evidência (fail-secure)
//!   6. Erro   → HTTP 451 (fail-secure: jamais encaminha em dúvida)
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
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use ulid::Ulid;
use buildtovalue_kernel::policy::{PolicyEngine, PolicyAction};

use crate::state::{AppState, PROXY_BLOCKED_TOTAL, PROXY_FORWARD_LATENCY_MS, PROXY_REQUESTS_TOTAL};
use super::common::{governance_url, FALLBACK_POLICY};

// Inline policy for proxy scan — same source as validate.rs
const DEFAULT_POLICY: &str = include_str!("../../../../data/policies/core/default.yaml");

/// Headers encaminhados ao upstream — whitelist explícita.
const FORWARD_HEADERS: &[&str] = &[
    "content-type",
    "authorization",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
];

#[derive(Serialize)]
struct ProxyGovernanceRequest {
    finding_count: u32,
    critical_count: u32,
    composite_risk: f32,
    action: String,
    hard_blocked: bool,
    matched_policies: Vec<String>,
    session_id: Option<String>,
    input_text: String,
    verdict_id: String,
    max_finding_confidence: f32,
    entropy: f32,
    total_chars: u32,
    blake3_hash: String,
    ip_risk: String,
    ip_jurisdiction: String,
    drift_level: String,
}

#[derive(Deserialize, Default)]
struct ProxyGovernanceVerdict {
    #[serde(default)]
    action: String,
}

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

    let input_text = String::from_utf8_lossy(&body).to_string();
    let verdict_id = format!("VRD-PROXY-{}", Ulid::new());

    // ── Kernel scan (síncrono, bloqueante) ─────────────────────────
    let scan_result = {
        let Ok(mut gk) = state.gatekeeper.lock() else {
            return block_response("Gatekeeper lock failed — fail-secure block");
        };

        let evidence = gk.scan_for_evidence(&input_text, 0u128);
        let findings = evidence.get_all_findings();

        let engine_result = PolicyEngine::from_yaml_str(DEFAULT_POLICY)
            .or_else(|_| PolicyEngine::from_yaml_str(FALLBACK_POLICY));
        let mut engine = match engine_result {
            Ok(e) => e,
            Err(_) => return block_response("Policy engine init failed — fail-secure block"),
        };
        let eval = engine.evaluate_full(&input_text, &findings);

        let policy_action = match eval.action {
            PolicyAction::Block   => "BLOCK",
            PolicyAction::Redact  => "REDACT",
            PolicyAction::Educate => "EDUCATE",
            PolicyAction::Log     => "LOG",
            PolicyAction::Allow   => "ALLOW",
        };

        let max_conf = findings.iter()
            .map(|f| f.confidence as f32 / 255.0)
            .fold(0.0_f32, f32::max);

        (
            evidence.finding_count as u32,
            evidence.critical_count as u32,
            evidence.composite_risk,
            policy_action.to_string(),
            eval.hard_blocked,
            eval.matched_policies,
            max_conf,
            evidence.stats.entropy,
            evidence.stats.total_chars,
            format!("{:016x}", evidence.original_request_hash),
        )
    };

    let (finding_count, critical_count, composite_risk, policy_action,
         hard_blocked, matched_policies, max_conf, entropy, total_chars, blake3_hash) = scan_result;

    // Fail-secure: hard block never reaches governance
    if hard_blocked {
        return block_response("Hard block — fail-secure");
    }

    // ── Governance /v1/decide (assíncrono) ─────────────────────────
    let gov_req = ProxyGovernanceRequest {
        finding_count,
        critical_count,
        composite_risk,
        action: policy_action.clone(),
        hard_blocked,
        matched_policies,
        session_id: None,
        input_text: input_text.clone(),
        verdict_id,
        max_finding_confidence: max_conf,
        entropy,
        total_chars,
        blake3_hash,
        ip_risk: "Low".to_string(),
        ip_jurisdiction: "XX".to_string(),
        drift_level: "None".to_string(),
    };

    let final_action = match state
        .http_client
        .post(format!("{}/v1/decide", governance_url()))
        .json(&gov_req)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            resp.json::<ProxyGovernanceVerdict>()
                .await
                .unwrap_or_default()
                .action
        }
        // Governance unavailable → fail-secure: always block
        _ => "BLOCK".to_string(),
    };

    if final_action != "ALLOW" {
        return block_response("Policy violation detected by BTV Trust OS");
    }

    // ── Forward ao upstream ─────────────────────────────────────────
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
