//! GET /metrics — Prometheus exposition format.

use axum::response::IntoResponse;
use prometheus::{Encoder, TextEncoder};

pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    encoder.encode(&metric_families, &mut buffer)
        .unwrap_or_default();

    (
        [("content-type", "text/plain; version=0.0.4")],
        String::from_utf8(buffer).unwrap_or_default(),
    )
}