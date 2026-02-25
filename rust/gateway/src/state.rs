use buildtovalue_kernel::gatekeeper::Gatekeeper;
use std::sync::Mutex;
use prometheus::{IntCounterVec, IntCounter, Histogram, HistogramOpts, opts, register_int_counter_vec, register_int_counter, register_histogram};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref DECISIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("btv_decisions_total", "Total decisions by action"),
        &["action"]
    ).unwrap();

    pub static ref MERCY_APPLIED_TOTAL: IntCounter = register_int_counter!(
        "btv_mercy_applied_total", "Total mercy applications (Gilligan)"
    ).unwrap();

    pub static ref HARD_BLOCKS_TOTAL: IntCounter = register_int_counter!(
        "btv_hard_blocks_total", "Total hard blocks"
    ).unwrap();

    pub static ref LATENCY_MS: Histogram = register_histogram!(
        HistogramOpts::new("btv_latency_ms", "Request latency in milliseconds")
            .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0])
    ).unwrap();

    pub static ref FINDINGS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("btv_findings_total", "Total findings by type"),
        &["type"]
    ).unwrap();

    pub static ref SANITIZE_TOTAL: IntCounter = register_int_counter!(
        "btv_sanitize_total", "Total sanitize requests"
    ).unwrap();

    pub static ref SANITIZE_MASKED_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("btv_sanitize_masked_total", "Total PII masked by type"),
        &["type"]
    ).unwrap();

    pub static ref RATE_LIMITED_TOTAL: IntCounter = register_int_counter!(
        "btv_rate_limited_total", "Total rate-limited requests"
    ).unwrap();

    pub static ref AUTH_REJECTED_TOTAL: IntCounter = register_int_counter!(
        "btv_auth_rejected_total", "Total rejected auth attempts"
    ).unwrap();

    pub static ref DECIDE_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("btv_decide_total", "Total /v1/decide requests by action (ADR-040)"),
        &["action"]
    ).unwrap();

    pub static ref DECIDE_LATENCY_MS: Histogram = register_histogram!(
        HistogramOpts::new("btv_decide_latency_ms", "/v1/decide latency in milliseconds")
            .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0])
    ).unwrap();

    pub static ref APPEALS_SUBMITTED_TOTAL: IntCounter = register_int_counter!(
        "btv_appeals_submitted_total", "Total appeals submitted (ADR-037)"
    ).unwrap();

    pub static ref APPEALS_RESOLVED_TOTAL: IntCounter = register_int_counter!(
        "btv_appeals_resolved_total", "Total appeals resolved (ADR-037)"
    ).unwrap();

}


impl Default for AppState {
    fn default() -> Self { Self::new() }
}
pub struct AppState {
    pub gatekeeper: Mutex<Gatekeeper>,
    pub http_client: reqwest::Client,
    pub start_time: std::time::Instant,
}

impl AppState {
    pub fn new() -> Self {
        // Force lazy_static init
        lazy_static::initialize(&DECISIONS_TOTAL);
        lazy_static::initialize(&MERCY_APPLIED_TOTAL);
        lazy_static::initialize(&HARD_BLOCKS_TOTAL);
        lazy_static::initialize(&LATENCY_MS);
        lazy_static::initialize(&FINDINGS_TOTAL);
        lazy_static::initialize(&SANITIZE_TOTAL);
        lazy_static::initialize(&SANITIZE_MASKED_TOTAL);
        lazy_static::initialize(&RATE_LIMITED_TOTAL);
        lazy_static::initialize(&AUTH_REJECTED_TOTAL);
        lazy_static::initialize(&DECIDE_TOTAL);
        lazy_static::initialize(&DECIDE_LATENCY_MS);
        lazy_static::initialize(&APPEALS_SUBMITTED_TOTAL);
        lazy_static::initialize(&APPEALS_RESOLVED_TOTAL);
        Self {
            gatekeeper: Mutex::new(Gatekeeper::new()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("Failed to create HTTP client"),
            start_time: std::time::Instant::now(),
        }
    }
}