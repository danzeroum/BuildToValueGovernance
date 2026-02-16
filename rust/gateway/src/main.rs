//! BTV Gateway v1.9.0 — Axum HTTP server (ADR-018)

use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod routes;
mod middleware;
mod state;

use state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "btv_gateway=info".into()))
        .init();

    let state = Arc::new(AppState::new());
    let app = routes::create_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("BTV Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}