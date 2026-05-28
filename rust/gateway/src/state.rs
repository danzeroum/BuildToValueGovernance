use buildtovalue_kernel::gatekeeper::Gatekeeper;
use buildtovalue_kernel::network::{IpClassifier, JurisdictionMapper};
use buildtovalue_kernel::session_guard::SessionTracker;
use buildtovalue_kernel::ledger::TenantStorageRouter;
use buildtovalue_kernel::security::tenant_key::TenantKeyDeriver;
use buildtovalue_kernel::keys::try_kernel_mac_key;
use std::path::PathBuf;
use std::sync::Mutex;
use prometheus::{
    opts, register_histogram, register_int_counter, register_int_counter_vec,
    Histogram, HistogramOpts, IntCounter, IntCounterVec,
};
use lazy_static::lazy_static;

// Boot-time metric registration.
// register_*! macros return Err only on duplicate metric names (programmer error
// caught at startup -- panic is the correct response).
//
// NOTE: #[allow] cannot be placed on a macro invocation site (lazy_static!);
// the compiler ignores it and emits unused_attribute with -D warnings.
// Pattern: each static initializer is wrapped in { #[allow(...)] { expr } }.
lazy_static! {
    pub static ref DECISIONS_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!("btv_decisions_total", "Total decisions by action"),
            &["action"]
        ).unwrap() }
    };

    pub static ref MERCY_APPLIED_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_mercy_applied_total", "Total mercy applications (Gilligan)"
        ).unwrap() }
    };

    pub static ref HARD_BLOCKS_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_hard_blocks_total", "Total hard blocks"
        ).unwrap() }
    };

    pub static ref LATENCY_MS: Histogram = {
        #[allow(clippy::unwrap_used)]
        { register_histogram!(
            HistogramOpts::new("btv_latency_ms", "Request latency in milliseconds")
                .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0])
        ).unwrap() }
    };

    pub static ref FINDINGS_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!("btv_findings_total", "Total findings by type"),
            &["type"]
        ).unwrap() }
    };

    pub static ref SANITIZE_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_sanitize_total", "Total sanitize requests"
        ).unwrap() }
    };

    pub static ref SANITIZE_MASKED_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!("btv_sanitize_masked_total", "Total PII masked by type"),
            &["type"]
        ).unwrap() }
    };

    pub static ref RATE_LIMITED_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_rate_limited_total", "Total rate-limited requests"
        ).unwrap() }
    };

    pub static ref AUTH_REJECTED_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_auth_rejected_total", "Total rejected auth attempts"
        ).unwrap() }
    };

    pub static ref DECIDE_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!("btv_decide_total", "Total /v1/decide requests by action (ADR-040)"),
            &["action"]
        ).unwrap() }
    };

    pub static ref DECIDE_LATENCY_MS: Histogram = {
        #[allow(clippy::unwrap_used)]
        { register_histogram!(
            HistogramOpts::new("btv_decide_latency_ms", "/v1/decide latency in milliseconds")
                .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0])
        ).unwrap() }
    };

    pub static ref APPEALS_SUBMITTED_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_appeals_submitted_total", "Total appeals submitted (ADR-037)"
        ).unwrap() }
    };

    pub static ref APPEALS_RESOLVED_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_appeals_resolved_total", "Total appeals resolved (ADR-037)"
        ).unwrap() }
    };

    pub static ref PIPELINE_RAWLS_DURATION: Histogram = {
        #[allow(clippy::unwrap_used)]
        { register_histogram!(
            HistogramOpts::new("btv_gateway_rawls_duration_ms", "Rawls stage proxy latency ms")
                .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0])
        ).unwrap() }
    };

    pub static ref PIPELINE_GILLIGAN_DURATION: Histogram = {
        #[allow(clippy::unwrap_used)]
        { register_histogram!(
            HistogramOpts::new("btv_gateway_gilligan_duration_ms", "Gilligan stage proxy latency ms")
                .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0])
        ).unwrap() }
    };

    pub static ref TRUST_ADJUSTMENTS_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!("btv_gateway_trust_adjustments_total", "Trust adjustments via gateway"),
            &["direction"]
        ).unwrap() }
    };

    pub static ref BIAS_GATE_VIOLATIONS_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_gateway_bias_gate_violations_total",
            "BiasGuardian gate violations detected via /health/bias"
        ).unwrap() }
    };

    // ── Proxy forward metrics (Fase 2 — proxy HTTP transparente) ──
    pub static ref PROXY_REQUESTS_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_proxy_requests_total", "Total requests intercepted by proxy"
        ).unwrap() }
    };

    pub static ref PROXY_BLOCKED_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_proxy_blocked_total", "Total proxy requests blocked by policy (HTTP 451)"
        ).unwrap() }
    };

    pub static ref PROXY_FORWARD_LATENCY_MS: Histogram = {
        #[allow(clippy::unwrap_used)]
        { register_histogram!(
            HistogramOpts::new("btv_proxy_forward_latency_ms", "Proxy forward round-trip latency ms")
                .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0])
        ).unwrap() }
    };
}

pub struct AppState {
    pub gatekeeper: Mutex<Gatekeeper>,
    pub ip_classifier: IpClassifier,           // ADR-044: stateless
    pub jurisdiction_mapper: JurisdictionMapper, // ADR-044: IP->jurisdicao
    pub session_tracker: Mutex<SessionTracker>, // ADR-044: stateful, por sessao
    pub http_client: reqwest::Client,
    pub start_time: std::time::Instant,
    /// ADR-0083: router de ledger por tenant (lazy, thread-safe).
    pub tenant_router: TenantStorageRouter,
    /// ADR-0083: derivador de TEK por tenant via HKDF-SHA256.
    pub tenant_deriver: TenantKeyDeriver,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        // Force lazy_static init at startup
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
        lazy_static::initialize(&PIPELINE_RAWLS_DURATION);
        lazy_static::initialize(&PIPELINE_GILLIGAN_DURATION);
        lazy_static::initialize(&TRUST_ADJUSTMENTS_TOTAL);
        lazy_static::initialize(&BIAS_GATE_VIOLATIONS_TOTAL);
        lazy_static::initialize(&PROXY_REQUESTS_TOTAL);
        lazy_static::initialize(&PROXY_BLOCKED_TOTAL);
        lazy_static::initialize(&PROXY_FORWARD_LATENCY_MS);

        // ADR-0083: base path for per-tenant ledger files.
        let tenant_data_dir: PathBuf = std::env::var("BTV_TENANT_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/data/tenants"));

        // TenantKeyDeriver uses the kernel MAC key (MKK) if already initialized
        // (production flow via main()); falls back to a dev sentinel otherwise
        // (integration tests that construct AppState directly).
        const DEV_SENTINEL: &[u8] = b"btv-dev-key-do-not-use-in-production";
        let tenant_deriver = TenantKeyDeriver::new(
            try_kernel_mac_key().unwrap_or(DEV_SENTINEL),
        );
        let tenant_router = TenantStorageRouter::new(
            tenant_data_dir,
            buildtovalue_kernel::ledger::remote::S3Config::default(),
        );

        Self {
            gatekeeper: Mutex::new(Gatekeeper::new()),
            ip_classifier: IpClassifier::new(),
            jurisdiction_mapper: JurisdictionMapper::new(),
            session_tracker: Mutex::new(SessionTracker::new()),
            // reqwest::Client::builder().build() only fails on invalid TLS config;
            // default builder has no custom TLS -- boot-time invariant.
            #[allow(clippy::expect_used)]
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("BTV boot invariant: reqwest default builder must succeed"),
            start_time: std::time::Instant::now(),
            tenant_router,
            tenant_deriver,
        }
    }
}
