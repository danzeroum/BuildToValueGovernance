//! gRPC Audit Exposer (ADR-0091) — server-streaming de `FairnessAuditEvent`
//! sobre Tonic, alimentado pelo **tail** dos JSONL locais escritos pelo
//! `JsonlAuditSink`.
//!
//! Topologia:
//! - Segundo listener (porta `GRPC_PORT`) erguido em paralelo ao HTTP no
//!   `main.rs`, compartilhando apenas o `audit_dir` (path) — não o `AppState`.
//! - O tailer abre os arquivos em **modo leitura**; jamais toca o `Mutex` de
//!   escrita do `JsonlAuditSink` → sem contenção no hot path de escrita.
//! - Backpressure por canal `mpsc` bounded com `send().await`: se o consumidor
//!   (ex: Java) está lento, o tailer apenas atrasa a leitura — o dado é durável
//!   no disco, então não há perda (distinto do drainer in-memory do commit 5,
//!   onde dropar era correto).
//! - Auth: interceptor que reusa `internal_auth::check_internal_key` contra o
//!   metadata `x-btv-internal-key`.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::audit::event::FairnessAuditEvent;
use crate::middleware::internal_auth::{
    check_internal_key, internal_secret_from_env, InternalSecret, KeyCheck,
};

/// Stubs gerados por `tonic-build` (ver `build.rs` + `proto/audit_exposer.proto`).
/// `clippy::all` desligado: código gerado não segue o lint estrito do crate.
pub mod pb {
    // Código gerado por tonic-build: desliga o lint group `all` e os lints de
    // restrição que o CI habilita por linha de comando (não cobertos por `all`).
    #![allow(clippy::all)]
    #![allow(clippy::clone_on_ref_ptr, clippy::unwrap_used, clippy::expect_used)]
    tonic::include_proto!("btv.audit.v1alpha");
}

use pb::audit_exposer_server::{AuditExposer, AuditExposerServer};

/// Chave do metadata gRPC (lowercase ASCII, como exige o protocolo HTTP/2).
const METADATA_KEY: &str = "x-btv-internal-key";

/// Intervalo de polling do tail (ADR-0091 §D2).
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Capacidade do canal de streaming por conexão. Bounded → backpressure.
const STREAM_CHANNEL_CAPACITY: usize = 1024;

lazy_static::lazy_static! {
    // register_*! falha só em nome duplicado (erro de programador no boot) —
    // panic é a resposta correta. #[allow] não pode ficar no site da macro
    // lazy_static!; envolve-se o initializer (mesmo padrão de state.rs).
    static ref GRPC_AUDIT_STREAMED_TOTAL: prometheus::IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { prometheus::register_int_counter_vec!(
            "btv_grpc_audit_streamed_total",
            "FairnessDecision events streamed over gRPC, by tenant",
            &["tenant"]
        ).unwrap() }
    };
}

/// Conversão determinística `FairnessAuditEvent` → mensagem de wire.
/// Os enums Rust são achatados para string via `serde` (fonte única do
/// formato textual; ver testes de serialização em `event.rs`).
pub(crate) fn event_to_proto(ev: &FairnessAuditEvent) -> pb::FairnessDecision {
    pb::FairnessDecision {
        schema_version: ev.schema_version.clone(),
        event_id: ev.event_id.clone(),
        ts_unix_ms: u64::try_from(ev.ts_unix_ms).unwrap_or(u64::MAX),
        tenant_id: ev.tenant_id.clone(),
        verdict_id: ev.verdict_id.clone(),
        fairness_mode: enum_to_str(&ev.fairness_mode),
        tenant_status: tenant_status_state(&ev.tenant_status),
        tentative_action: ev.tentative_action.clone(),
        applied_action: ev.applied_action.clone(),
        composed_action: ev.composed_action.clone(),
        composition_changed_action: ev.composition_changed_action,
        apply_override: ev.apply_override,
        rawls_violation: ev.rawls_violation,
        jonas_critical: ev.jonas_critical,
        jonas_warning: ev.jonas_warning,
        hard_block: ev.hard_block,
        human_review_required: ev.human_review_required,
        governance_error_codes: ev.governance_error_codes.clone(),
        legacy_error_code: ev.legacy_error_code.clone(),
    }
}

/// `FairnessMode` serializa como string nua ("shadow"). Extrai esse texto.
fn enum_to_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|val| val.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// `TenantStatus` serializa como objeto `{"state":"active",...}`. Projeta só
/// o discriminante `state` para o wire.
fn tenant_status_state<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|val| {
            val.get("state")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// Implementação do serviço. Stateless além do `audit_dir`.
pub struct GrpcAuditExposer {
    audit_dir: PathBuf,
}

impl GrpcAuditExposer {
    pub fn new(audit_dir: PathBuf) -> Self {
        Self { audit_dir }
    }
}

type DecisionStream = Pin<Box<dyn Stream<Item = Result<pb::FairnessDecision, Status>> + Send>>;

#[tonic::async_trait]
impl AuditExposer for GrpcAuditExposer {
    type StreamAuditEventsStream = DecisionStream;

    async fn stream_audit_events(
        &self,
        request: Request<pb::StreamRequest>,
    ) -> Result<Response<Self::StreamAuditEventsStream>, Status> {
        let tenant_filter = request.into_inner().tenant_id;
        let audit_dir = self.audit_dir.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(STREAM_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            // offset[path] = bytes já consumidos (sempre numa fronteira de linha).
            let mut offsets: HashMap<PathBuf, u64> = HashMap::new();
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            loop {
                ticker.tick().await;

                let files = discover_files(&audit_dir, &tenant_filter).await;
                for path in files {
                    let offset = offsets.entry(path.clone()).or_insert(0);
                    match read_new_events(&path, *offset).await {
                        Ok((events, new_offset)) => {
                            *offset = new_offset;
                            for ev in events {
                                let tenant = ev.tenant_id.clone();
                                let proto = event_to_proto(&ev);
                                // send().await aplica backpressure (sem perda;
                                // dado é durável no JSONL). Erro = cliente saiu.
                                if tx.send(Ok(proto)).await.is_err() {
                                    return;
                                }
                                GRPC_AUDIT_STREAMED_TOTAL
                                    .with_label_values(&[tenant.as_str()])
                                    .inc();
                            }
                        }
                        Err(e) => {
                            tracing::debug!(path = %path.display(), error = %e,
                                "grpc audit tail: leitura falhou (provável arquivo ainda inexistente)");
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Resolve a lista de arquivos `events.jsonl` a tailar. `tenant_filter`
/// vazio → varre todos os subdirs de `audit_dir` (descobre tenants novos a
/// cada tick); preenchido → apenas aquele tenant.
async fn discover_files(audit_dir: &std::path::Path, tenant_filter: &str) -> Vec<PathBuf> {
    if !tenant_filter.is_empty() {
        return vec![audit_dir.join(tenant_filter).join("events.jsonl")];
    }
    let mut out = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(audit_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.path().is_dir() {
                out.push(entry.path().join("events.jsonl"));
            }
        }
    }
    out
}

/// Lê linhas completas novas de `path` a partir de `offset`. Devolve os
/// eventos parseados e o novo offset (avança só até o último `\n`, deixando
/// qualquer linha parcial para o próximo tick).
async fn read_new_events(
    path: &std::path::Path,
    offset: u64,
) -> std::io::Result<(Vec<FairnessAuditEvent>, u64)> {
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    if len <= offset {
        return Ok((Vec::new(), offset));
    }
    file.seek(SeekFrom::Start(offset)).await?;
    let mut bytes = vec![0u8; (len - offset) as usize];
    file.read_exact(&mut bytes).await?;

    let last_nl = match bytes.iter().rposition(|&b| b == b'\n') {
        Some(pos) => pos,
        None => return Ok((Vec::new(), offset)), // linha ainda incompleta
    };
    let consumed = last_nl + 1;
    let mut events = Vec::new();
    for line in bytes[..=last_nl].split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<FairnessAuditEvent>(line) {
            Ok(ev) => events.push(ev),
            Err(e) => tracing::warn!(error = %e, "grpc audit tail: linha JSONL inválida — skip"),
        }
    }
    Ok((events, offset + consumed as u64))
}

/// Interceptor de auth gRPC — espelha `InternalAuthLayer` (ADR-0089 §D2).
/// Tipo nomeado (em vez de closure) para que o tipo do serviço seja
/// nomeável e reusável por `serve_grpc` e pelos testes.
#[derive(Clone)]
struct AuthInterceptor {
    secret: InternalSecret,
}

impl tonic::service::Interceptor for AuthInterceptor {
    /// `result_large_err`: a assinatura `Result<_, Status>` é imposta pelo
    /// trait do tonic; `Status` é grande mas inevitável aqui.
    #[allow(clippy::result_large_err)]
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        let provided = req
            .metadata()
            .get(METADATA_KEY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .as_bytes();
        match check_internal_key(&self.secret, provided) {
            KeyCheck::Ok => Ok(req),
            KeyCheck::WrongKey => Err(Status::unauthenticated("")),
            KeyCheck::Disabled => Err(Status::unavailable("internal auth disabled")),
        }
    }
}

type ExposerService =
    tonic::service::interceptor::InterceptedService<AuditExposerServer<GrpcAuditExposer>, AuthInterceptor>;

/// Monta o serviço gRPC com o interceptor de auth (segredo lido do ambiente).
fn build_service(audit_dir: PathBuf) -> ExposerService {
    let interceptor = AuthInterceptor {
        secret: internal_secret_from_env(),
    };
    AuditExposerServer::with_interceptor(GrpcAuditExposer::new(audit_dir), interceptor)
}

/// Sobe o servidor gRPC do exposer numa porta. Chamado em paralelo ao HTTP
/// no `main.rs`.
pub async fn serve_grpc(audit_dir: PathBuf, addr: SocketAddr) -> Result<(), tonic::transport::Error> {
    tracing::info!("BTV Gateway gRPC AuditExposer listening on {}", addr);
    Server::builder()
        .add_service(build_service(audit_dir))
        .serve(addr)
        .await
}

/// Variante que serve sobre um `TcpListener` já vinculado — útil para testes
/// (porta efêmera) e para binding gracioso controlado pelo caller.
/// Consumido pelo crate de testes de integração, não pelo bin → `dead_code`
/// localizado (o bin re-declara o módulo e não chama esta fn).
#[allow(dead_code)]
pub async fn serve_grpc_with_listener(
    audit_dir: PathBuf,
    listener: tokio::net::TcpListener,
) -> Result<(), tonic::transport::Error> {
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    Server::builder()
        .add_service(build_service(audit_dir))
        .serve_with_incoming(incoming)
        .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fairness_mode::FairnessMode;
    use crate::tenant_status::TenantStatus;

    fn sample(tenant: &str) -> FairnessAuditEvent {
        let mut e = FairnessAuditEvent::new(
            tenant.to_string(),
            "VRD-1".to_string(),
            1_700_000_000_000,
            FairnessMode::Shadow,
            TenantStatus::Active,
        );
        e.applied_action = "REDACT".to_string();
        e.rawls_violation = true;
        e.governance_error_codes = vec!["E160".to_string()];
        e
    }

    #[test]
    fn event_to_proto_is_faithful() {
        let ev = sample("acme");
        let p = event_to_proto(&ev);
        assert_eq!(p.schema_version, "v1alpha");
        assert_eq!(p.tenant_id, "acme");
        assert_eq!(p.fairness_mode, "shadow");
        assert_eq!(p.tenant_status, "active");
        assert_eq!(p.applied_action, "REDACT");
        assert!(p.rawls_violation);
        assert_eq!(p.governance_error_codes, vec!["E160".to_string()]);
        assert_eq!(p.ts_unix_ms, 1_700_000_000_000);
    }

    #[tokio::test]
    async fn read_new_events_tails_complete_lines_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("events.jsonl");
        // Duas linhas completas + uma parcial (sem \n final).
        let l1 = serde_json::to_string(&sample("acme")).unwrap();
        let l2 = serde_json::to_string(&sample("acme")).unwrap();
        std::fs::write(&path, format!("{l1}\n{l2}\n{{\"partial\"")).unwrap();

        let (events, offset) = read_new_events(&path, 0).await.unwrap();
        assert_eq!(events.len(), 2, "linha parcial não deve ser emitida");
        // offset aponta para o início da linha parcial.
        let expected = (l1.len() + 1 + l2.len() + 1) as u64;
        assert_eq!(offset, expected);

        // Segunda chamada a partir do offset: nada novo (parcial continua).
        let (events2, offset2) = read_new_events(&path, offset).await.unwrap();
        assert!(events2.is_empty());
        assert_eq!(offset2, offset);
    }
}
