//! `InternalAuthLayer` — autenticação dos endpoints `/internal/v1/*`
//! (ADR-0089 §D2).
//!
//! Compara `X-BTV-Internal-Key` recebido com `BTV_INTERNAL_SECRET` em
//! **tempo constante** via `subtle::ConstantTimeEq` — sem timing
//! side-channel para enumeração de chaves.
//!
//! Falhas devolvem HTTP 401 com corpo vazio (menos sinal para
//! enumeração). Em produção, `BTV_INTERNAL_SECRET` ausente → todos os
//! endpoints `/internal/*` respondem 503 (fail-secure: rotas internas
//! não devem ficar acessíveis sem autenticação).
//!
//! Em dev (sem `BTV_INTERNAL_SECRET` e `BTV_ENV != production`), o
//! layer **bloqueia tudo** com 503 mesmo assim — operadores devem
//! configurar a chave explicitamente para testar localmente.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower::{Layer, Service};
use zeroize::Zeroizing;

/// Nome do header/metadata da chave interna. Reusado pelo layer HTTP e
/// pelo interceptor gRPC (ADR-0091) — gRPC normaliza para lowercase.
pub(crate) const HEADER_NAME: &str = "X-BTV-Internal-Key";
const ENV_VAR: &str = "BTV_INTERNAL_SECRET";
/// Comprimento mínimo recomendado (256 bits = 32 bytes hex = 64 chars
/// hex ou 44 chars base64). Sentinel anti-misconfiguration.
const MIN_SECRET_BYTES: usize = 32;

/// Segredo interno compartilhado. `None` → autenticação desligada
/// (fail-secure: rejeita tudo).
pub(crate) type InternalSecret = Arc<Option<Zeroizing<Vec<u8>>>>;

/// Resultado da verificação de chave, agnóstico ao protocolo. O caller
/// traduz para o status apropriado (HTTP 401/503 ou gRPC
/// unauthenticated/unavailable).
pub(crate) enum KeyCheck {
    /// Chave válida — prosseguir.
    Ok,
    /// Chave ausente ou incorreta.
    WrongKey,
    /// `BTV_INTERNAL_SECRET` ausente/curto — endpoint desligado.
    Disabled,
}

/// Lê `BTV_INTERNAL_SECRET` do ambiente aplicando o piso de
/// `MIN_SECRET_BYTES`. Fonte única de verdade para o layer HTTP e o
/// interceptor gRPC.
pub(crate) fn internal_secret_from_env() -> InternalSecret {
    let key = std::env::var(ENV_VAR).ok().and_then(|s| {
        if s.len() < MIN_SECRET_BYTES {
            tracing::warn!(
                "{ENV_VAR} tem menos de {MIN_SECRET_BYTES} bytes — \
                 endpoints internos ficarão desligados"
            );
            None
        } else {
            Some(Zeroizing::new(s.into_bytes()))
        }
    });
    Arc::new(key)
}

/// Compara `provided` contra o segredo esperado em tempo constante.
/// Checagem de comprimento primeiro (curto-circuito só no tamanho, sem
/// vazar timing do conteúdo), depois `ct_eq`.
pub(crate) fn check_internal_key(expected: &InternalSecret, provided: &[u8]) -> KeyCheck {
    match expected.as_ref() {
        None => KeyCheck::Disabled,
        Some(expected_bytes) => {
            if provided.len() == expected_bytes.len()
                && bool::from(provided.ct_eq(expected_bytes.as_slice()))
            {
                KeyCheck::Ok
            } else {
                KeyCheck::WrongKey
            }
        }
    }
}

#[derive(Clone)]
pub struct InternalAuthLayer {
    /// `None` → endpoints `/internal/*` respondem 503 em toda chamada.
    /// `Some(key)` → comparação constant-time contra este valor.
    expected: Arc<Option<Zeroizing<Vec<u8>>>>,
}

impl InternalAuthLayer {
    /// Lê `BTV_INTERNAL_SECRET` do ambiente. Se ausente, em produção
    /// permanece `None` (todas as chamadas → 503). Em dev, igual — não
    /// há "modo permissivo" para endpoints internos.
    pub fn from_env() -> Self {
        Self {
            expected: internal_secret_from_env(),
        }
    }

    /// Constructor explícito para tests. Aceita qualquer comprimento.
    #[allow(dead_code)]
    pub fn with_key(key: Vec<u8>) -> Self {
        Self {
            expected: Arc::new(Some(Zeroizing::new(key))),
        }
    }

    /// Layer "desligado" — sempre devolve 503. Útil para testar o
    /// caminho de fallback sem mexer no env.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            expected: Arc::new(None),
        }
    }
}

impl<S> Layer<S> for InternalAuthLayer {
    type Service = InternalAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InternalAuthService {
            inner,
            expected: Arc::clone(&self.expected),
        }
    }
}

#[derive(Clone)]
pub struct InternalAuthService<S> {
    inner: S,
    expected: Arc<Option<Zeroizing<Vec<u8>>>>,
}

impl<S> Service<Request<Body>> for InternalAuthService<S>
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

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let expected = Arc::clone(&self.expected);
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let provided = req
                .headers()
                .get(HEADER_NAME)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .as_bytes();
            let reject_with = |status: StatusCode| {
                Response::builder()
                    .status(status)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            };
            let response = match check_internal_key(&expected, provided) {
                KeyCheck::Ok => None,
                KeyCheck::WrongKey => Some(reject_with(StatusCode::UNAUTHORIZED)),
                KeyCheck::Disabled => Some(reject_with(StatusCode::SERVICE_UNAVAILABLE)),
            };
            match response {
                Some(rejection) => Ok(rejection),
                None => inner.call(req).await,
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use axum_test::TestServer;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn server(layer: InternalAuthLayer) -> TestServer {
        let app = Router::new().route("/ping", get(ok_handler)).layer(layer);
        TestServer::new(app).unwrap()
    }

    #[tokio::test]
    async fn correct_key_passes() {
        let key = b"this-is-a-very-long-test-secret-key-32bytes".to_vec();
        let layer = InternalAuthLayer::with_key(key.clone());
        let s = server(layer);
        let res = s
            .get("/ping")
            .add_header(
                axum::http::HeaderName::from_static("x-btv-internal-key"),
                axum::http::HeaderValue::from_bytes(&key).unwrap(),
            )
            .await;
        res.assert_status_ok();
        res.assert_text("ok");
    }

    #[tokio::test]
    async fn wrong_key_returns_401() {
        let layer = InternalAuthLayer::with_key(b"expected-key".to_vec());
        let s = server(layer);
        let res = s
            .get("/ping")
            .add_header(
                axum::http::HeaderName::from_static("x-btv-internal-key"),
                axum::http::HeaderValue::from_static("wrong-key"),
            )
            .await;
        assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED);
        // Corpo vazio — menos sinal para enumeração.
        res.assert_text("");
    }

    #[tokio::test]
    async fn missing_header_returns_401() {
        let layer = InternalAuthLayer::with_key(b"expected-key".to_vec());
        let s = server(layer);
        let res = s.get("/ping").await;
        assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn disabled_layer_returns_503_even_with_correct_attempts() {
        let layer = InternalAuthLayer::disabled();
        let s = server(layer);
        let res = s.get("/ping").await;
        assert_eq!(res.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn different_lengths_dont_panic() {
        // Sanidade: chave provida com tamanho diferente NÃO chega no
        // ct_eq (early-return), evitando panic do subtle.
        let layer = InternalAuthLayer::with_key(b"32-byte-key-aaaaaaaaaaaaaaaaaa".to_vec());
        let s = server(layer);
        let res = s
            .get("/ping")
            .add_header(
                axum::http::HeaderName::from_static("x-btv-internal-key"),
                axum::http::HeaderValue::from_static("short"),
            )
            .await;
        assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED);
    }
}
