//! BTV Gateway v0.1.0-alpha.1 — Axum HTTP server (ADR-018)

use std::net::SocketAddr;
use std::sync::Arc;
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
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "btv_gateway=info".into()))
        .init();

    // S-01 / PROP-031: initialize the kernel MAC key from BTV_HMAC_KEY before
    // any scan runs. Must happen before worker fork; we are still single-threaded
    // here because tokio::main has just constructed the runtime.
    buildtovalue_kernel::keys::init_kernel_mac_key()
        .map_err(|e| format!("kernel MAC key init failed: {e}"))?;

    let state = Arc::new(AppState::new());
    // Captura o audit_dir antes de mover o state para o router — o exposer
    // gRPC (ADR-0091) taila os JSONL em {audit_dir}/{tenant}/events.jsonl.
    let audit_dir = state.audit_dir.clone();
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

    // HTTP (Axum) e gRPC (Tonic AuditExposer) rodam em paralelo; se qualquer
    // um terminar (erro ou shutdown), o processo encerra.
    let http = async {
        axum::serve(listener, app)
            .await
            .map_err(|e| format!("axum::serve terminated: {e}"))
    };
    let grpc = async {
        audit::grpc_exposer::serve_grpc(audit_dir, grpc_addr)
            .await
            .map_err(|e| format!("tonic::serve terminated: {e}"))
    };
    tokio::try_join!(http, grpc)?;
    Ok(())
}