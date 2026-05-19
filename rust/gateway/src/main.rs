//! BTV Gateway v1.9.0 — Axum HTTP server (ADR-018)

use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod routes;
mod middleware;
mod state;

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
    let app = routes::create_router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("BTV Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("axum::serve terminated: {e}"))?;
    Ok(())
}