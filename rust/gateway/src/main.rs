//! BTV Gateway v0.1.0-alpha.1 — Axum HTTP server (ADR-018)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod routes;
mod middleware;
mod state;
mod fairness_mode;
mod tenant_status;
mod policy_loader;
mod audit;
// nota: routes::internal e middleware::internal_auth são compilados
// via mod routes; / mod middleware; — não precisam ser top-level.

use state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Passo 13: init OTel before tracing so the layer is available at subscriber init.
    // Returns None (NoopTracerProvider) when OTEL_EXPORTER_OTLP_ENDPOINT is absent.
    let _otel_provider = init_otel();
    let otel_layer = _otel_provider.as_ref().map(|p: &opentelemetry_sdk::trace::TracerProvider| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::OpenTelemetryLayer::new(p.tracer("btv-gateway"))
    });

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "btv_gateway=info".into()))
        .with(otel_layer)
        .init();

    // S-01 / PROP-031: initialize the kernel MAC key from BTV_HMAC_KEY before
    // any scan runs. Must happen before worker fork; we are still single-threaded
    // here because tokio::main has just constructed the runtime.
    buildtovalue_kernel::keys::init_kernel_mac_key()
        .map_err(|e| format!("kernel MAC key init failed: {e}"))?;

    let state = Arc::new(AppState::new());

    // CRITICO-10: warm all tenant policies before the server accepts its first
    // request. Missing policies_dir is a warning (dev-friendly); individual
    // tenant failures are logged as errors and the tenant is marked Degraded.
    policy_loader::warm_policies(
        &state.policies_dir,
        &state.jonas_monitor,
        &state.fairness_modes,
        &state.tenant_statuses,
    )
    .await;

    // Captura o audit_dir antes de mover o state para o router — o exposer
    // gRPC (ADR-0091) taila os JSONL em {audit_dir}/{tenant}/events.jsonl.
    let audit_dir = state.audit_dir.clone();
    // Clone do handle do drainer para o drain-on-SIGTERM. Retido aqui antes
    // de mover o state para o router: quando o router é droppado (servidores
    // parados), esta vira a única referência → `Arc::try_unwrap` devolve o
    // `JoinHandle` para aguardarmos o drainer esvaziar a fila.
    let audit_handle = state.audit_handle();
    let app = routes::create_router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let grpc_port: u16 = std::env::var("GRPC_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9090);
    let grpc_addr = SocketAddr::from(([0, 0, 0, 0], grpc_port));

    tracing::info!("BTV Gateway listening on {} (HTTP) + {} (gRPC)", addr, grpc_addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;

    // Sinal de shutdown compartilhado pelos dois servidores. Uma task ouve
    // SIGTERM/Ctrl-C e seta `true`; cada servidor aguarda essa transição
    // para iniciar o graceful shutdown (drena conexões ativas e retorna).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("sinal de shutdown recebido; iniciando graceful shutdown");
        let _ = shutdown_tx.send(true);
    });

    // HTTP (Axum) e gRPC (Tonic AuditExposer) rodam em paralelo; ambos
    // param ao receber o sinal de shutdown.
    let http = {
        let mut rx = shutdown_rx.clone();
        async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.wait_for(|v| *v).await;
                })
                .await
                .map_err(|e| format!("axum::serve terminated: {e}"))
        }
    };
    let grpc = {
        let mut rx = shutdown_rx.clone();
        async move {
            audit::grpc_exposer::serve_grpc(audit_dir, grpc_addr, async move {
                let _ = rx.wait_for(|v| *v).await;
            })
            .await
            .map_err(|e| format!("tonic::serve terminated: {e}"))
        }
    };
    tokio::try_join!(http, grpc)?;

    // Drain-on-SIGTERM: os servidores pararam, então o router (e o
    // `Arc<AppState>` dentro dele) já foi droppado → o `AuditChannel`
    // fechou → o drainer está drenando a fila + `flush_all`. Aguardamos
    // seu término com timeout para não pendurar o shutdown indefinidamente.
    match Arc::try_unwrap(audit_handle) {
        Ok(handle) => match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(())) => tracing::info!("audit drainer drenado graciosamente"),
            Ok(Err(e)) => tracing::error!(error = %e, "audit drainer join falhou"),
            Err(_) => tracing::warn!("audit drainer: timeout de 5s no drain — eventos podem ter sido perdidos"),
        },
        Err(_) => tracing::warn!("audit handle ainda referenciado; pulando drain await"),
    }
    Ok(())
}

/// Initialises the OTel OTLP tracer when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
/// Returns the `TracerProvider` so the caller keeps it alive for the process
/// lifetime (dropping it would flush and shut down the exporter). Returns `None`
/// when the env var is absent — tracing continues with the fmt layer only (CI-safe).
fn init_otel() -> Option<opentelemetry_sdk::trace::TracerProvider> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok()?;

    use opentelemetry_otlp::WithExportConfig;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .map_err(|e| eprintln!("OTel OTLP exporter init failed (tracing degraded): {e}"))
        .ok()?;

    let resource = opentelemetry_sdk::Resource::new(vec![
        opentelemetry::KeyValue::new("service.name", "btv-gateway"),
    ]);

    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    eprintln!("OTel OTLP tracer initialised: endpoint={endpoint}");
    Some(provider)
}

/// Aguarda um sinal de término do processo: `SIGTERM` (orquestrador, ex.
/// Kubernetes/Docker stop) ou Ctrl-C (`SIGINT`, dev local). Resolve no
/// primeiro que chegar. Sem `unwrap`/`expect` (CI roda clippy estrito):
/// se o handler de SIGTERM não puder ser instalado, cai para esperar
/// apenas o Ctrl-C.
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("falha ao instalar handler de Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "falha ao instalar handler de SIGTERM; só Ctrl-C disponível");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}