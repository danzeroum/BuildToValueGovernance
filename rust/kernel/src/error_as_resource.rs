//! Error-as-a-Resource — BuildToValue Governance
//!
//! Implementa o princípio do API_ETHICS_GUIDE.md §3:
//! todo 4xx retorna um objeto estruturado com referência ao ADR
//! que causou o bloqueio e URL de contestação.
//!
//! Invariantes:
//! - Zero alocação heap nos caminhos de erro mais frequentes (&'static str)
//! - Nunca expor stack trace ou detalhes internos
//! - verdict_id obrigatório em todo erro contestável
//! - Funções ≤ 50 linhas

use serde::Serialize;

/// Erro ético estruturado — retornado em todos os 4xx do BTV.
/// Ref: API_ETHICS_GUIDE.md §3, ADR-052
#[derive(Debug, Serialize)]
pub struct EthicalError {
    pub error_code: &'static str,
    pub ethical_ground: &'static str,
    pub adr_reference: &'static str,
    pub remediation: &'static str,
    pub appeal_url: &'static str,
    /// Hash BLAKE3 da TechnicalEvidence — âncora de contestação.
    /// None apenas quando o erro ocorre ANTES da evidência ser gerada.
    pub verdict_id: Option<String>,
    /// ISO8601 — deadline do ContestabilitySLA 24h.
    /// None quando o erro não é contestável (ex: erro de contrato).
    pub contestable_until: Option<String>,
}

/// HTTP status code semântico para serialização.
#[derive(Debug, Clone, Copy)]
pub enum EthicalHttpStatus {
    Forbidden = 403,
    BadRequest = 400,
    TooManyRequests = 429,
    InternalError = 500,
}

impl EthicalError {
    /// E120 — BiasDeclaration ausente ou inválida.
    /// Não contestável: erro de contrato do cliente.
    pub fn bias_declaration_missing() -> (Self, EthicalHttpStatus) {
        let err = Self {
            error_code: "E120",
            ethical_ground: "BiasDeclaration ausente ou inválida",
            adr_reference: "https://docs.buildtovalue.org/adrs/0010-bias-declaration-mandate",
            remediation: "https://docs.buildtovalue.org/guides/bias-fix",
            appeal_url: "/api/v1/appeals",
            verdict_id: None,
            contestable_until: None,
        };
        (err, EthicalHttpStatus::Forbidden)
    }

    /// E130 — Violação de política ativa (bloqueio ético com evidência).
    /// Contestável: SLA 24h.
    pub fn policy_violation(
        adr_slug: &'static str,
        verdict_id: String,
        contestable_until: String,
    ) -> (Self, EthicalHttpStatus) {
        let err = Self {
            error_code: "E130",
            ethical_ground: "Decisão bloqueada por política ativa",
            adr_reference: adr_slug,
            remediation: "https://docs.buildtovalue.org/guides/policy-remediation",
            appeal_url: "/api/v1/appeals",
            verdict_id: Some(verdict_id),
            contestable_until: Some(contestable_until),
        };
        (err, EthicalHttpStatus::Forbidden)
    }

    /// E140 — DIR abaixo do threshold estatístico.
    /// Contestável: SLA 24h.
    pub fn dir_threshold_violation(
        verdict_id: String,
        contestable_until: String,
    ) -> (Self, EthicalHttpStatus) {
        let err = Self {
            error_code: "E140",
            ethical_ground: "Disparate Impact Ratio abaixo do threshold",
            adr_reference: "https://docs.buildtovalue.org/adrs/0008-dir-threshold",
            remediation: "https://docs.buildtovalue.org/guides/dir-remediation",
            appeal_url: "/api/v1/appeals",
            verdict_id: Some(verdict_id),
            contestable_until: Some(contestable_until),
        };
        (err, EthicalHttpStatus::Forbidden)
    }

    /// E160 — Assinatura HMAC inválida (Tampering detectado pelo EarlyGuard).
    /// Não contestável: violação de integridade.
    pub fn hmac_tampering_detected() -> (Self, EthicalHttpStatus) {
        let err = Self {
            error_code: "E160",
            ethical_ground: "Assinatura HMAC inválida — possível adulteração de payload",
            adr_reference: "https://docs.buildtovalue.org/adrs/early-guard-tamper-detection",
            remediation: "https://docs.buildtovalue.org/guides/hmac-signing",
            appeal_url: "/api/v1/appeals",
            verdict_id: None,
            contestable_until: None,
        };
        (err, EthicalHttpStatus::BadRequest)
    }

    /// E429 — Z-Score de frequência excedido (self-preservation mode).
    /// Não contestável.
    pub fn rate_limit_z_score_exceeded() -> (Self, EthicalHttpStatus) {
        let err = Self {
            error_code: "E429",
            ethical_ground: "Tenant excedeu Z-Score de frequência (self-preservation mode ativo)",
            adr_reference: "https://docs.buildtovalue.org/adrs/early-guard-throttle",
            remediation: "https://docs.buildtovalue.org/guides/rate-limit",
            appeal_url: "/api/v1/appeals",
            verdict_id: None,
            contestable_until: None,
        };
        (err, EthicalHttpStatus::TooManyRequests)
    }

    /// E500 — Plugin ético falhou (fail-secure BLOCK).
    /// Contestável: falha de plugin pode ser revisada.
    pub fn ethics_plugin_failed(
        plugin_id: &'static str,
        plugin_version: &'static str,
        verdict_id: String,
        contestable_until: String,
    ) -> (Self, EthicalHttpStatus) {
        // plugin_id e plugin_version são capturados para post-mortem.
        // Logados pelo caller — não expostos no corpo da resposta.
        let _ = (plugin_id, plugin_version); // usado pelo caller para log
        let err = Self {
            error_code: "E500",
            ethical_ground: "Motor de governança falhou — fail-secure BLOCK aplicado",
            adr_reference: "https://docs.buildtovalue.org/adrs/fail-secure-kernel",
            remediation: "https://docs.buildtovalue.org/guides/plugin-failure",
            appeal_url: "/api/v1/appeals",
            verdict_id: Some(verdict_id),
            contestable_until: Some(contestable_until),
        };
        (err, EthicalHttpStatus::InternalError)
    }
}

/// Headers de rate limit — injetados em TODAS as respostas pelo middleware Axum.
/// Zero heap: valores primitivos copiados por valor.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitHeaders {
    pub limit: u64,
    pub remaining: u64,
    pub reset_unix: u64,
    /// "full" | "integrity" — modo de sampling ativo
    pub sampling_mode: &'static str,
    /// "v1" | "v2" — versão de governança ativa
    pub governance_version: &'static str,
}

impl RateLimitHeaders {
    /// Serializa para array de (nome, valor) para Axum HeaderMap.
    pub fn to_header_pairs(&self) -> [(&'static str, String); 5] {
        [
            ("X-RateLimit-Limit", self.limit.to_string()),
            ("X-RateLimit-Remaining", self.remaining.to_string()),
            ("X-RateLimit-Reset", self.reset_unix.to_string()),
            ("X-BTV-Sampling-Mode", self.sampling_mode.to_string()),
            ("X-BTV-Governance-Version", self.governance_version.to_string()),
        ]
    }

    /// Headers adicionais quando throttled (Z-Score excedido).
    pub fn throttle_headers(retry_after_secs: u64) -> [(&'static str, String); 2] {
        [
            ("X-BTV-Throttle-Reason", "z_score_exceeded".to_string()),
            ("Retry-After", retry_after_secs.to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bias_missing_is_not_contestable() {
        let (err, status) = EthicalError::bias_declaration_missing();
        assert_eq!(err.error_code, "E120");
        assert!(err.verdict_id.is_none());
        assert!(err.contestable_until.is_none());
        assert!(matches!(status, EthicalHttpStatus::Forbidden));
    }

    #[test]
    fn policy_violation_has_verdict_id() {
        let (err, _) = EthicalError::policy_violation(
            "https://docs.buildtovalue.org/adrs/0008",
            "blake3:abc123".to_string(),
            "2026-05-29T02:35:00Z".to_string(),
        );
        assert!(err.verdict_id.is_some());
        assert!(err.contestable_until.is_some());
    }

    #[test]
    fn rate_limit_headers_no_heap_fields() {
        let headers = RateLimitHeaders {
            limit: 1000,
            remaining: 847,
            reset_unix: 1748390400,
            sampling_mode: "full",
            governance_version: "v1",
        };
        let pairs = headers.to_header_pairs();
        assert_eq!(pairs[0].0, "X-RateLimit-Limit");
        assert_eq!(pairs[3].0, "X-BTV-Sampling-Mode");
    }
}
