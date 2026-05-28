//! TenantExtractor — Axum middleware (ADR-0084).
//!
//! Extrai `tenant_id` do Bearer JWT e insere como `TenantId` extension.
//! Handlers recebem `TenantId` tipada — nunca JWT raw.
//!
//! Em produção, `BTV_JWT_SECRET` deve estar configurado; em dev sem a
//! variável, decodifica sem verificar assinatura com aviso de log.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use buildtovalue_kernel::api::error_as_resource::EthicalError;
use buildtovalue_kernel::security::tenant_key::validate_tenant_id;
use buildtovalue_kernel::ledger::DEFAULT_TENANT_ID;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::Arc;
use tower::{Layer, Service};

/// Extensão de request tipada que carrega o `tenant_id` validado.
/// Injetada pelo `TenantExtractor`; acessada nos handlers via
/// `Extension<TenantId>`.
#[derive(Debug, Clone)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Claims JWT mínimos que o BTV reconhece.
#[derive(Debug, Deserialize)]
struct BtvClaims {
    /// Tenant que emitiu o token. Ausente → "default".
    tenant_id: Option<String>,
    /// Expiration. Validação de expiração é feita pelo `jsonwebtoken` via
    /// `Validation::validate_exp` quando há `BTV_JWT_SECRET`; o campo é mantido
    /// no payload bruto para integridade forense do JWT (auditoria pode validar
    /// `exp` independentemente do crate).
    #[allow(dead_code)]
    exp: Option<u64>,
    /// Subject — reservado para telemetria de identidade ativa (SecOps).
    /// Não usado em decisão de tenant para evitar acoplamento entre identity
    /// e tenancy.
    #[allow(dead_code)]
    sub: Option<String>,
}

/// Layer Tower que envolve os handlers com extração de tenant.
#[derive(Clone)]
pub struct TenantExtractorLayer {
    jwt_secret: Arc<Option<Vec<u8>>>,
}

impl TenantExtractorLayer {
    /// Lê `BTV_JWT_SECRET` do ambiente. Se ausente em dev mode, continua
    /// com extração insegura e log de aviso.
    pub fn from_env() -> Self {
        let secret = std::env::var("BTV_JWT_SECRET")
            .ok()
            .map(|s| s.into_bytes());

        if secret.is_none() {
            let env = std::env::var("BTV_ENV").unwrap_or_else(|_| "development".into());
            if env == "production" {
                panic!(
                    "BTV_JWT_SECRET must be set in production. \
                     Generate with: openssl rand -hex 32"
                );
            }
            tracing::warn!(
                "BTV_JWT_SECRET not set — JWT tenant extraction running \
                 in INSECURE mode (dev only)"
            );
        }

        Self {
            jwt_secret: Arc::new(secret),
        }
    }
}

impl<S> Layer<S> for TenantExtractorLayer {
    type Service = TenantExtractorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantExtractorService {
            inner,
            jwt_secret: Arc::clone(&self.jwt_secret),
        }
    }
}

#[derive(Clone)]
pub struct TenantExtractorService<S> {
    inner: S,
    jwt_secret: Arc<Option<Vec<u8>>>,
}

impl<S> Service<Request<Body>> for TenantExtractorService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let jwt_secret = Arc::clone(&self.jwt_secret);
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let tenant_id = extract_tenant_from_request(&req, &jwt_secret);

            match tenant_id {
                Ok(tid) => {
                    req.extensions_mut().insert(TenantId(tid));
                    inner.call(req).await
                }
                Err(response) => Ok(response),
            }
        })
    }
}

/// Extrai e valida `tenant_id` da requisição.
/// Retorna `Ok(tenant_id)` em sucesso ou `Err(Response)` com E131 em falha.
fn extract_tenant_from_request(
    req: &Request<Body>,
    jwt_secret: &Option<Vec<u8>>,
) -> Result<String, Response<Body>> {
    let bearer_token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string());

    let claims = match bearer_token {
        None => return Ok(DEFAULT_TENANT_ID.to_string()),
        Some(token) => decode_tenant_claims(&token, jwt_secret),
    };

    let tenant_id = match claims {
        Ok(c) => c.tenant_id.unwrap_or_else(|| DEFAULT_TENANT_ID.to_string()),
        Err(()) => {
            // JWT malformado mas não vazio — fail-secure para "default"
            // só em dev (sem secret). Em prod, jwt_secret é Some → decode
            // teria validado; chegamos aqui apenas se o token é inválido.
            tracing::warn!("JWT decode failed; routing to default tenant");
            DEFAULT_TENANT_ID.to_string()
        }
    };

    // Valida o tenant_id extraído antes de qualquer acesso ao router.
    if let Err(_) = validate_tenant_id(&tenant_id) {
        let instance = req.uri().path().to_string();
        let err = EthicalError::tenant_isolation_violation(
            tenant_id.clone(),
            "<validated>",
            None,
        )
        .with_instance(instance);

        let body = serde_json::to_string(&err).unwrap_or_else(|_| {
            r#"{"type":"E131","status":403}"#.to_string()
        });

        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/problem+json")
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()));

        return Err(response);
    }

    Ok(tenant_id)
}

/// Decodifica o token JWT e retorna os claims BTV.
/// Com `jwt_secret = Some(secret)`: valida assinatura HS256.
/// Com `jwt_secret = None` (dev): extrai claims do payload base64 sem verificação.
fn decode_tenant_claims(token: &str, jwt_secret: &Option<Vec<u8>>) -> Result<BtvClaims, ()> {
    match jwt_secret {
        Some(secret) => {
            let key = DecodingKey::from_secret(secret);
            let mut validation = Validation::new(Algorithm::HS256);
            validation.validate_exp = true;

            decode::<BtvClaims>(token, &key, &validation)
                .map(|data| data.claims)
                .map_err(|e| {
                    tracing::warn!("JWT validation failed: {e}");
                })
        }
        None => {
            // Dev mode: decodifica o payload base64 diretamente sem verificar assinatura.
            // Evita depender de feature flags ou APIs instáveis do jsonwebtoken.
            let parts: Vec<&str> = token.splitn(3, '.').collect();
            if parts.len() != 3 {
                return Err(());
            }
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| {
                tracing::debug!("JWT base64 decode failed: {e}");
            })?;
            serde_json::from_slice::<BtvClaims>(&payload_bytes).map_err(|e| {
                tracing::debug!("JWT claims deserialize failed: {e}");
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_req_with_bearer(token: &str) -> Request<Body> {
        Request::builder()
            .uri("/api/v1/decisions")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn make_req_without_auth() -> Request<Body> {
        Request::builder()
            .uri("/api/v1/decisions")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn no_bearer_header_routes_to_default() {
        let req = make_req_without_auth();
        let result = extract_tenant_from_request(&req, &None);
        assert_eq!(result.unwrap(), DEFAULT_TENANT_ID);
    }

    #[test]
    fn invalid_tenant_id_in_jwt_returns_e131_response() {
        // Craft a JWT with tenant_id = "UPPERCASE" (invalid)
        use jsonwebtoken::{encode, EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct BadClaims {
            tenant_id: String,
            sub: String,
        }
        let token = encode(
            &Header::default(),
            &BadClaims {
                tenant_id: "UPPERCASE".to_string(),
                sub: "test".to_string(),
            },
            &EncodingKey::from_secret(b""),
        )
        .unwrap();

        let req = make_req_with_bearer(&token);
        let result = extract_tenant_from_request(&req, &None);
        assert!(result.is_err(), "expected E131 response for invalid tenant_id");
        let resp = result.unwrap_err();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn valid_tenant_id_in_jwt_is_extracted() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct GoodClaims {
            tenant_id: String,
            sub: String,
        }
        let token = encode(
            &Header::default(),
            &GoodClaims {
                tenant_id: "acme-corp".to_string(),
                sub: "user1".to_string(),
            },
            &EncodingKey::from_secret(b""),
        )
        .unwrap();

        let req = make_req_with_bearer(&token);
        let result = extract_tenant_from_request(&req, &None);
        assert_eq!(result.unwrap(), "acme-corp");
    }

    #[test]
    fn jwt_without_tenant_id_claim_routes_to_default() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct NoClaim {
            sub: String,
        }
        let token = encode(
            &Header::default(),
            &NoClaim {
                sub: "user2".to_string(),
            },
            &EncodingKey::from_secret(b""),
        )
        .unwrap();

        let req = make_req_with_bearer(&token);
        let result = extract_tenant_from_request(&req, &None);
        assert_eq!(result.unwrap(), DEFAULT_TENANT_ID);
    }

    #[test]
    fn tenant_id_newtype_as_str() {
        let t = TenantId("acme".to_string());
        assert_eq!(t.as_str(), "acme");
    }
}
