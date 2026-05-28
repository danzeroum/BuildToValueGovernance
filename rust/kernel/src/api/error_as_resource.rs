//! Error-as-a-Resource — RFC 7807 (`application/problem+json`).
//!
//! Implementa o contrato definido em `docs/API_ETHICS_GUIDE.md` §3
//! e ADR-0082. Toda resposta `4xx`/`5xx` do BTV serializa como
//! `EthicalError` com campos padrão RFC 7807 na raiz e extensões
//! BTV-específicas (verdict_id, audit_log_id, appeal_url, etc.) sob
//! `extensions`.
//!
//! Invariantes:
//! - Zero `panic!`/`unwrap` (fail-secure).
//! - `&'static str` onde possível; sem alocação heap fora do construtor.
//! - Nunca vaza paths internos, stack traces ou nomes de arquivos `.rs`.

use serde::Serialize;

/// Content-Type RFC 7807 que toda resposta de erro do BTV deve usar.
pub const PROBLEM_JSON_CONTENT_TYPE: &str = "application/problem+json";

/// Erro ético estruturado conforme RFC 7807.
///
/// Campos padrão na raiz (`type`, `title`, `status`, `detail`, `instance`);
/// campos BTV-específicos sob `extensions`. Ver `docs/API_ETHICS_GUIDE.md` §3.
#[derive(Debug, Serialize)]
pub struct EthicalError {
    /// URI absoluta identificando o tipo de erro.
    #[serde(rename = "type")]
    pub type_uri: &'static str,
    /// Resumo curto, legível por humanos.
    pub title: &'static str,
    /// Código HTTP equivalente.
    pub status: u16,
    /// Explicação específica desta ocorrência.
    pub detail: String,
    /// URI da requisição que originou o erro.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Extensões BTV (campos não-RFC 7807).
    pub extensions: BtvExtensions,
}

/// Extensões BTV ao envelope RFC 7807.
///
/// Ver ADR-0082 (cláusula de compatibilidade): qualquer campo adicionado
/// após v1.0 deve ser `Option<T>`.
#[derive(Debug, Serialize)]
pub struct BtvExtensions {
    pub error_code: &'static str,
    pub ethical_ground: &'static str,
    pub adr_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict_id: Option<String>,
    /// UUID v7 (ordenável por tempo) apontando para a entrada no ledger
    /// forense (ADR-0052). Sem ele, o DPO não consegue instruir contestação.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_log_id: Option<String>,
    pub appeal_url: &'static str,
    /// ISO-8601. `None` quando o erro for de contrato (não contestável).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contestable_until: Option<String>,
    /// Metadata opcional injetada pelo kernel (decision_id tipado, contexto
    /// adicional). Só serializa na resposta HTTP — fora do hot path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl EthicalError {
    /// E120 — BiasDeclaration ausente ou inválida (ADR-0010).
    /// Erro de contrato: não contestável.
    pub fn bias_declaration_missing(audit_log_id: Option<String>) -> Self {
        Self {
            type_uri: "https://docs.buildtovalue.org/errors/E120",
            title: "BiasDeclaration ausente",
            status: 400,
            detail: "A requisição não inclui BiasDeclaration assinada exigida pelo ADR-0010.".to_string(),
            instance: None,
            extensions: BtvExtensions {
                error_code: "E120",
                ethical_ground: "BiasDeclaration ausente ou inválida",
                adr_reference: "https://docs.buildtovalue.org/adrs/0010-bias-declaration-mandate".to_string(),
                verdict_id: None,
                audit_log_id,
                appeal_url: "/api/v1/appeals",
                contestable_until: None,
                metadata: None,
            },
        }
    }

    /// E130 — Decisão bloqueada por política ativa. Contestável.
    ///
    /// `metadata` permite injeção tipada de contexto (ex: `decision_id`,
    /// regra específica acionada) sem `HashMap` no hot path.
    pub fn policy_violation(
        adr_slug: &str,
        verdict_id: Option<String>,
        audit_log_id: Option<String>,
        deadline_iso8601: String,
        metadata: Option<serde_json::Value>,
    ) -> Self {
        Self {
            type_uri: "https://docs.buildtovalue.org/errors/E130",
            title: "Decisão bloqueada por política",
            status: 403,
            detail: "A decisão foi bloqueada por política ativa do tenant. Veja o ADR referenciado para detalhes da regra aplicada.".to_string(),
            instance: None,
            extensions: BtvExtensions {
                error_code: "E130",
                ethical_ground: "Decisão bloqueada por política ativa",
                adr_reference: format!("https://docs.buildtovalue.org/adrs/{}", adr_slug),
                verdict_id,
                audit_log_id,
                appeal_url: "/api/v1/appeals",
                contestable_until: Some(deadline_iso8601),
                metadata,
            },
        }
    }

    /// E429 — Tenant excedeu Z-Score de frequência (Early Guard self-preservation).
    /// Erro de infraestrutura: não contestável.
    pub fn rate_limit_z_score(audit_log_id: Option<String>) -> Self {
        Self {
            type_uri: "https://docs.buildtovalue.org/errors/E429",
            title: "Rate limit excedido",
            status: 429,
            detail: "Tenant excedeu Z-Score de frequência (μ + 3σ em janela de 60s). Throttling automático ativo.".to_string(),
            instance: None,
            extensions: BtvExtensions {
                error_code: "E429",
                ethical_ground: "Tenant excedeu Z-Score de frequência (self-preservation mode)",
                adr_reference: "https://docs.buildtovalue.org/adrs/early-guard-throttle".to_string(),
                verdict_id: None,
                audit_log_id,
                appeal_url: "/api/v1/appeals",
                contestable_until: None,
                metadata: None,
            },
        }
    }

    /// Anexa a URI da requisição como `instance` (campo RFC 7807).
    pub fn with_instance(mut self, instance: String) -> Self {
        self.instance = Some(instance);
        self
    }
}

/// Modo de amostragem do Speed Layer (Lambda Governance).
#[derive(Debug, Clone, Copy)]
pub enum SamplingMode {
    Full,
    Integrity,
}

impl SamplingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SamplingMode::Full => "full",
            SamplingMode::Integrity => "integrity",
        }
    }
}

/// Headers padrão de rate limit + sampling mode.
///
/// Ver `docs/API_ETHICS_GUIDE.md` §5.2. Retorna pares `(nome, valor)`
/// prontos para anexar à resposta HTTP. Aloca apenas para os valores
/// numéricos (não há `&'static str` para `u64::to_string`).
pub fn attach_rate_limit_headers(
    limit: u64,
    remaining: u64,
    reset_epoch_seconds: u64,
    mode: SamplingMode,
) -> [(&'static str, String); 4] {
    [
        ("X-RateLimit-Limit", limit.to_string()),
        ("X-RateLimit-Remaining", remaining.to_string()),
        ("X-RateLimit-Reset", reset_epoch_seconds.to_string()),
        ("X-BTV-Sampling-Mode", mode.as_str().to_string()),
    ]
}

/// Calcula o header `X-BTV-Verdict-Signature` usando a primitiva HMAC-SHA256
/// de `crate::security::signing`. Garante autenticidade da resposta contra
/// proxies reversos que possam alterar payload em trânsito.
///
/// Retorna a tupla `(header_name, "hmac-sha256=<hex>")`.
pub fn verdict_signature_header(
    signer: &crate::security::signing::SigningKeyManager,
    body: &[u8],
) -> (&'static str, String) {
    let signature = signer.sign(body);
    (
        "X-BTV-Verdict-Signature",
        format!("hmac-sha256={}", hex::encode(signature)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Garante que serialização nunca vaza paths internos ou nomes de
    /// arquivos `.rs` — protege contra exposição acidental de detalhes
    /// de implementação na resposta HTTP. Ver ADR-0082 §6 (enforcement).
    fn assert_no_internal_leak(json: &str) {
        assert!(
            !json.contains("src/"),
            "vazamento de path interno detectado: {json}"
        );
        assert!(
            !json.contains(".rs:"),
            "vazamento de linha de código detectado: {json}"
        );
        assert!(
            !json.contains("/home/"),
            "vazamento de path absoluto detectado: {json}"
        );
    }

    #[test]
    fn bias_declaration_missing_produces_rfc7807() {
        let err = EthicalError::bias_declaration_missing(Some(
            "01927c4f-7e23-7a1b-9c4f-1f8e4c8a9d12".to_string(),
        ));
        let json = serde_json::to_string(&err).expect("serialize");

        assert!(json.contains("\"type\":\"https://docs.buildtovalue.org/errors/E120\""));
        assert!(json.contains("\"status\":400"));
        assert!(json.contains("\"error_code\":\"E120\""));
        assert!(json.contains("\"audit_log_id\":\"01927c4f-7e23-7a1b-9c4f-1f8e4c8a9d12\""));
        // contestable_until ausente (None) — não deve aparecer no JSON
        assert!(!json.contains("contestable_until"));
        assert_no_internal_leak(&json);
    }

    #[test]
    fn policy_violation_includes_deadline_and_metadata() {
        let meta = serde_json::json!({"decision_id": "abc-123", "rule": "after_hours"});
        let err = EthicalError::policy_violation(
            "0072-gilligan-sla-mercy-algorithm",
            Some("verdict-xyz".to_string()),
            Some("01927c4f-7e23-7a1b-9c4f-1f8e4c8a9d12".to_string()),
            "2026-05-29T12:00:00Z".to_string(),
            Some(meta),
        );
        let json = serde_json::to_string(&err).expect("serialize");

        assert!(json.contains("\"status\":403"));
        assert!(json.contains("\"contestable_until\":\"2026-05-29T12:00:00Z\""));
        assert!(json.contains("\"verdict_id\":\"verdict-xyz\""));
        assert!(json.contains("\"rule\":\"after_hours\""));
        assert!(json.contains("0072-gilligan-sla-mercy-algorithm"));
        assert_no_internal_leak(&json);
    }

    #[test]
    fn rate_limit_z_score_is_429_and_not_contestable() {
        let err = EthicalError::rate_limit_z_score(None);
        let json = serde_json::to_string(&err).expect("serialize");

        assert!(json.contains("\"status\":429"));
        assert!(json.contains("\"error_code\":\"E429\""));
        assert!(!json.contains("contestable_until"));
        assert!(!json.contains("audit_log_id"));
        assert_no_internal_leak(&json);
    }

    #[test]
    fn with_instance_adds_request_uri() {
        let err = EthicalError::bias_declaration_missing(None)
            .with_instance("/api/v1/decisions".to_string());
        let json = serde_json::to_string(&err).expect("serialize");
        assert!(json.contains("\"instance\":\"/api/v1/decisions\""));
    }

    #[test]
    fn rate_limit_headers_have_correct_names() {
        let headers = attach_rate_limit_headers(1000, 847, 1748390400, SamplingMode::Full);
        assert_eq!(headers[0].0, "X-RateLimit-Limit");
        assert_eq!(headers[0].1, "1000");
        assert_eq!(headers[1].0, "X-RateLimit-Remaining");
        assert_eq!(headers[1].1, "847");
        assert_eq!(headers[2].0, "X-RateLimit-Reset");
        assert_eq!(headers[3].0, "X-BTV-Sampling-Mode");
        assert_eq!(headers[3].1, "full");
    }

    #[test]
    fn sampling_mode_integrity_serializes_correctly() {
        let headers = attach_rate_limit_headers(100, 0, 0, SamplingMode::Integrity);
        assert_eq!(headers[3].1, "integrity");
    }

    #[test]
    fn content_type_constant_is_rfc7807() {
        assert_eq!(PROBLEM_JSON_CONTENT_TYPE, "application/problem+json");
    }
}
