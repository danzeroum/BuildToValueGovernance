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
        let req = request.into_inner();
        let tenant_filter = req.tenant_id;
        let resume_after = req.resume_after_event_id;
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
                    // Primeira vez que vemos este arquivo: se há cursor de
                    // retomada (ADR-0092 §D3), busca o offset logo após o
                    // evento do cursor; senão começa do início. Custo O(n) da
                    // busca incorre uma única vez por arquivo.
                    let offset = match offsets.get(&path) {
                        Some(o) => *o,
                        None => {
                            let init = if resume_after.is_empty() {
                                0
                            } else {
                                seek_after_event_id(&path, &resume_after).await
                            };
                            offsets.insert(path.clone(), init);
                            init
                        }
                    };
                    match read_new_events(&path, offset).await {
                        Ok((events, new_offset)) => {
                            offsets.insert(path.clone(), new_offset);
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

/// Cursor de retomada (ADR-0092 §D3): varre `path` do início procurando a
/// linha cujo evento tem `event_id == target` e devolve o offset de bytes
/// logo após essa linha (ponto de retomada do tail).
///
/// Não encontrado (cursor de tenant distinto, arquivo rotacionado, ou
/// arquivo recém-criado) → devolve `0`: o arquivo é tailado desde o início.
/// A entrega é **at-least-once**; o consumidor deduplica por `event_id`.
/// Só conta linhas completas (terminadas em `\n`); uma linha parcial no fim
/// interrompe a busca. Busca linear O(tamanho do arquivo), executada uma
/// única vez por arquivo (rotação é responsabilidade de ops — ADR-0091 §D5).
async fn seek_after_event_id(path: &std::path::Path, target: &str) -> u64 {
    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return 0; // arquivo ainda não existe → tail desde o início quando surgir
    };
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).await.is_err() {
        return 0;
    }
    let mut pos: u64 = 0;
    for line in buf.split_inclusive(|&b| b == b'\n') {
        if line.last() != Some(&b'\n') {
            break; // linha parcial no fim — para antes dela
        }
        pos += line.len() as u64;
        let content = &line[..line.len() - 1];
        if content.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_slice::<FairnessAuditEvent>(content) {
            if ev.event_id == target {
                return pos; // offset logo após a linha do cursor
            }
        }
    }
    0 // cursor não encontrado → retoma do início (at-least-once)
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
/// no `main.rs`. `shutdown` é um future que, ao resolver, dispara o
/// graceful shutdown do Tonic (drain-on-SIGTERM): para de aceitar conexões
/// novas e deixa as ativas terminarem antes de retornar.
pub async fn serve_grpc(
    audit_dir: PathBuf,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    tracing::info!("BTV Gateway gRPC AuditExposer listening on {}", addr);
    Server::builder()
        .add_service(build_service(audit_dir))
        .serve_with_shutdown(addr, shutdown)
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

    /// Escreve `n` eventos completos e devolve (path, event_ids na ordem).
    async fn write_events(dir: &std::path::Path, n: usize) -> (PathBuf, Vec<String>) {
        let path = dir.join("events.jsonl");
        let mut ids = Vec::with_capacity(n);
        let mut body = String::new();
        for i in 0..n {
            let mut e = sample("acme");
            e.verdict_id = format!("VRD-{i}");
            ids.push(e.event_id.clone());
            body.push_str(&serde_json::to_string(&e).unwrap());
            body.push('\n');
        }
        tokio::fs::write(&path, body).await.unwrap();
        (path, ids)
    }

    #[tokio::test]
    async fn seek_after_event_id_resumes_after_cursor() {
        // 10 eventos; retoma após o 5º (índice 4) → recebe os eventos 6..=10.
        let tmp = tempfile::TempDir::new().unwrap();
        let (path, ids) = write_events(tmp.path(), 10).await;

        let offset = seek_after_event_id(&path, &ids[4]).await;
        assert!(offset > 0, "cursor encontrado deve dar offset > 0");

        let (events, _) = read_new_events(&path, offset).await.unwrap();
        assert_eq!(events.len(), 5, "deve retomar nos 5 eventos após o cursor");
        assert_eq!(events[0].event_id, ids[5], "primeiro evento é o seguinte ao cursor");
        assert_eq!(events[4].event_id, ids[9]);
    }

    #[tokio::test]
    async fn seek_after_event_id_not_found_replays_from_start() {
        // Cursor ausente (tenant distinto / rotação) → offset 0 = at-least-once.
        let tmp = tempfile::TempDir::new().unwrap();
        let (path, _ids) = write_events(tmp.path(), 3).await;

        let offset = seek_after_event_id(&path, "00000000-0000-0000-0000-000000000000").await;
        assert_eq!(offset, 0, "cursor não encontrado → retoma do início");

        let (events, _) = read_new_events(&path, offset).await.unwrap();
        assert_eq!(events.len(), 3, "todos os eventos são reentregues");
    }

    #[tokio::test]
    async fn seek_after_last_event_yields_end_offset() {
        // Retomar após o último evento → offset no fim → nada novo até chegar
        // um evento posterior (sem replay).
        let tmp = tempfile::TempDir::new().unwrap();
        let (path, ids) = write_events(tmp.path(), 4).await;

        let offset = seek_after_event_id(&path, &ids[3]).await;
        let (events, _) = read_new_events(&path, offset).await.unwrap();
        assert!(events.is_empty(), "nada após o último evento");
    }
}
