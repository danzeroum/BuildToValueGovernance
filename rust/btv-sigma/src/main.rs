//! btv-sigma — Guardian of Σ (Log Authority)
//!
//! Constitutional role: Σ is the fourth element of the BTV institution ⟨L, E, J, Σ⟩
//! (Paper 5, Definition 3.1). It is NOT infrastructure — it is an independent authority
//! operated under separate custody from the System Operator.
//!
//! Paper 2, Axiom III-C: K_priv is not accessible to the System Operator.
//! See DEPLOYMENT.md for key isolation requirements.
mod api;
mod merkle;
mod signer;
mod store;

use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let log_signer = signer::LogSigner::generate();
    let verifying_key = log_signer.verifying_key();

    // Print the verifying key for out-of-band pinning in LogClient instances.
    // Paper 2, Case D: this key MUST be obtained out-of-band, NOT from the log API.
    eprintln!("=== BTV-SIGMA LOG AUTHORITY ===");
    eprintln!("Verifying key (hex): {}", hex::encode(verifying_key.as_bytes()));
    eprintln!("Pin this key via BTV_LOG_VERIFYING_KEY in all LogClient instances.");
    eprintln!("NEVER obtain this key from the /append or /root endpoints.");
    eprintln!("===============================");

    let state = Arc::new(api::AppState {
        store: Arc::new(store::InMemoryStore::new()),
        signer: log_signer,
    });

    let app = api::router(state);
    let addr = "0.0.0.0:3100";
    let listener = tokio::net::TcpListener::bind(addr).await
        .unwrap_or_else(|e| panic!("Failed to bind {addr}: {e}"));
    tracing::info!("btv-sigma listening on {addr}");
    axum::serve(listener, app).await
        .unwrap_or_else(|e| panic!("Server error: {e}"));
}
