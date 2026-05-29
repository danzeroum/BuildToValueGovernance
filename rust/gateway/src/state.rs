use buildtovalue_kernel::gatekeeper::Gatekeeper;
use buildtovalue_kernel::network::{IpClassifier, JurisdictionMapper};
use buildtovalue_kernel::session_guard::SessionTracker;
use buildtovalue_kernel::ledger::TenantStorageRouter;
use buildtovalue_kernel::security::tenant_key::TenantKeyDeriver;
use buildtovalue_kernel::statistics::{JonasMonitor, RawlsMonitor};
use buildtovalue_kernel::keys::try_kernel_mac_key;
use crate::fairness_mode::FairnessModeRegistry;
use crate::tenant_status::TenantStatusRegistry;
use crate::audit::drainer::{spawn_drainer, AuditChannel};
use crate::audit::sink::{AuditSink, JsonlAuditSink, MultiAuditSink, StdoutAuditSink};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
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
    /// ADR-0086 + ADR-0088: monitor de fairness Rawls (DIR). Compartilhado
    /// via outer `Arc<AppState>` do main.rs — sem `Arc` interno por D1
    /// do ADR-0088 (síncrono, sem `tokio::spawn`).
    pub rawls_monitor: RawlsMonitor,
    /// ADR-0087 + ADR-0088: monitor de drift populacional Jonas (PSI).
    /// Storage-agnóstico: baselines precisam ser instalados explicitamente
    /// via `install_baseline()` no boot (operador) ou em testes. Filesystem
    /// loading (walk em `policies/*/drift_baseline.yaml`) é out-of-scope
    /// deste ADR — endpoint `/internal/v1/reload-policy` planejado para
    /// ADR-0089.
    pub jonas_monitor: JonasMonitor,
    /// ADR-0088 §D3: registry de modo de execução fairness por tenant.
    /// `Disabled` é o default fail-safe para tenants não declarados —
    /// explicit opt-in (operador instala modo via `install()` no boot).
    pub fairness_modes: FairnessModeRegistry,
    /// ADR-0089 §D1 — estado runtime por tenant (Initializing/Active/Degraded).
    /// Default `Active` para tenants sem entry (decisão documentada no
    /// header do módulo `tenant_status`).
    pub tenant_statuses: TenantStatusRegistry,
    /// ADR-0089 §D2 — diretório raiz das policies fairness por tenant.
    /// Resolvido de `BTV_POLICIES_DIR` em `AppState::new()` (uma vez,
    /// sem races em testes paralelos).
    pub policies_dir: PathBuf,
    /// audit-sink-local §D2 — diretório raiz dos JSONL de auditoria.
    /// Resolvido de `BTV_AUDIT_DIR` em `AppState::new()` (uma vez, sem
    /// races em testes paralelos), mesma disciplina de `policies_dir`.
    pub audit_dir: PathBuf,
    /// audit-sink-local §D4 — handle de emissão não-bloqueante para o
    /// drainer (MPSC bounded + `try_send`). `Clone` barato; consumido no
    /// hot path do `decide_handler`.
    pub audit_tx: AuditChannel,
    /// Handle do drainer task. Mantido vivo enquanto o `AppState` existir
    /// (drop fecha o canal → drainer encerra). Consumido pelo shutdown
    /// gracioso (drain-on-SIGTERM): `main` guarda um clone do `Arc` via
    /// `audit_handle()` e o aguarda após os servidores pararem.
    _audit_handle: Arc<JoinHandle<()>>,
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

        // audit-sink-local Commit 5: canal de auditoria + drainer.
        // Sink default = JSONL per-tenant + stdout estruturado (tee).
        // `spawn_drainer` cria o task consumidor único (MPSC bounded).
        let audit_dir = resolve_audit_dir();
        let sink: Arc<dyn AuditSink> = build_default_audit_sink(&audit_dir);
        let (audit_tx, audit_handle) = spawn_drainer(sink);

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
            // ADR-0088 Commit 4: monitores fairness + registry de modo.
            // Default::default() é equivalente a constructors vazios
            // (sem baselines, sem modos declarados). Operador é responsável
            // por install_baseline + install_mode no boot via leitura de
            // policies/*. Em testes, AppState::new() já fornece estado
            // limpo; testes que exercitam fairness instalam manualmente.
            rawls_monitor: RawlsMonitor::default(),
            jonas_monitor: JonasMonitor::default(),
            fairness_modes: FairnessModeRegistry::default(),
            tenant_statuses: TenantStatusRegistry::default(),
            policies_dir: resolve_policies_dir(),
            audit_dir: audit_dir.clone(),
            audit_tx,
            _audit_handle: Arc::new(audit_handle),
        }
    }

    /// Clone barato do handle do drainer, para o shutdown gracioso em
    /// `main`. `main` retém este `Arc` antes de mover o `AppState` para o
    /// router; quando o router é droppado (servidores parados), a única
    /// referência restante é esta → `Arc::try_unwrap` devolve o
    /// `JoinHandle` para ser aguardado (drain-on-SIGTERM).
    pub fn audit_handle(&self) -> Arc<JoinHandle<()>> {
        Arc::clone(&self._audit_handle)
    }

    /// Constructor para testes que injeta `policies_dir` arbitrário.
    /// Evita race em `std::env::set_var` quando testes paralelos
    /// configuram diretórios diferentes. Demais campos seguem `new()`.
    #[allow(dead_code)]
    pub fn with_policies_dir(policies_dir: PathBuf) -> Self {
        let mut s = Self::new();
        s.policies_dir = policies_dir;
        s
    }

    /// Constructor para testes que injeta `audit_dir` arbitrário, recriando
    /// sink+drainer apontados para o diretório de teste. Mesma disciplina
    /// anti-race de `with_policies_dir`. Demais campos seguem `new()`.
    #[allow(dead_code)]
    pub fn with_audit_dir(audit_dir: PathBuf) -> Self {
        let mut s = Self::new();
        let sink: Arc<dyn AuditSink> = build_default_audit_sink(&audit_dir);
        let (audit_tx, audit_handle) = spawn_drainer(sink);
        s.audit_dir = audit_dir;
        s.audit_tx = audit_tx;
        s._audit_handle = Arc::new(audit_handle);
        s
    }
}

/// ADR-0089 §D2 — resolução de `BTV_POLICIES_DIR`. Default em prod:
/// `/etc/btv/policies`. Default em dev: `./policies`.
fn resolve_policies_dir() -> PathBuf {
    if let Ok(s) = std::env::var("BTV_POLICIES_DIR") {
        return PathBuf::from(s);
    }
    if std::env::var("BTV_ENV").as_deref() == Ok("production") {
        PathBuf::from("/etc/btv/policies")
    } else {
        PathBuf::from("./policies")
    }
}

/// audit-sink-local §D2 — resolução de `BTV_AUDIT_DIR`. Default em prod:
/// `/var/log/btv/audit`. Default em dev: `./data/audit`.
fn resolve_audit_dir() -> PathBuf {
    if let Ok(s) = std::env::var("BTV_AUDIT_DIR") {
        return PathBuf::from(s);
    }
    if std::env::var("BTV_ENV").as_deref() == Ok("production") {
        PathBuf::from("/var/log/btv/audit")
    } else {
        PathBuf::from("./data/audit")
    }
}

/// Sink default do gateway: tee JSONL per-tenant + stdout estruturado.
/// Recebe `&Path` (não `&PathBuf`) para evitar `clippy::ptr_arg`;
/// `JsonlAuditSink::new` consome um `PathBuf` owned via `to_path_buf`.
fn build_default_audit_sink(audit_dir: &std::path::Path) -> Arc<dyn AuditSink> {
    let jsonl: Arc<dyn AuditSink> = Arc::new(JsonlAuditSink::new(audit_dir.to_path_buf()));
    let stdout: Arc<dyn AuditSink> = Arc::new(StdoutAuditSink);
    Arc::new(MultiAuditSink::new(vec![jsonl, stdout]))
}

/// Resultado de `AppState::evict_tenant` — bools por componente para
/// resposta HTTP do endpoint DELETE `/internal/v1/tenants/{tenant_id}`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvictionReport {
    pub router: bool,
    pub jonas: bool,
    pub rawls: bool,
    pub fairness_mode: bool,
    pub status: bool,
}

impl EvictionReport {
    /// `true` se algo foi removido em qualquer componente.
    #[allow(dead_code)]
    pub fn any(&self) -> bool {
        self.router || self.jonas || self.rawls || self.fairness_mode || self.status
    }
}

impl AppState {
    /// Helper para o decide_handler (Commit 5): resolve o modo do tenant
    /// uma vez por requisição, evitando duas leituras do `RwLock` no hot
    /// path quando `populates_explain()` e `enforces_action()` são
    /// consultados separadamente.
    pub fn fairness_mode_for(&self, tenant_id: &str) -> crate::fairness_mode::FairnessMode {
        self.fairness_modes.mode_for(tenant_id)
    }

    /// ADR-0089 §D3 — Eager cleanup orquestrado em 5 componentes,
    /// nesta ordem: `TenantStorageRouter` (drop `Arc<DurableLedger>`),
    /// `JonasMonitor`, `RawlsMonitor`, `FairnessModeRegistry`,
    /// `TenantStatusRegistry`.
    ///
    /// Sem cancelamento de tasks: D1 ADR-0088 mantém síncrono — não há
    /// background tasks por tenant para cancelar. Idempotente em tenant
    /// inexistente.
    pub async fn evict_tenant(&self, tenant_id: &str) -> EvictionReport {
        EvictionReport {
            router: self.tenant_router.evict_tenant(tenant_id).await,
            jonas: self.jonas_monitor.remove_tenant(tenant_id),
            rawls: self.rawls_monitor.remove_tenant(tenant_id),
            fairness_mode: self.fairness_modes.remove(tenant_id),
            status: self.tenant_statuses.remove(tenant_id),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fairness_mode::FairnessMode;
    use buildtovalue_kernel::statistics::{
        GroupClass, JonasBaselineLoader, OutcomeBucket,
    };

    fn fresh_state() -> AppState {
        AppState::new()
    }

    // `AppState::new()` spawna o drainer de auditoria (`tokio::spawn`),
    // exigindo um runtime ativo — daí `#[tokio::test]` nestes unit tests.
    #[tokio::test]
    async fn fresh_state_has_default_fairness_components() {
        let s = fresh_state();
        assert_eq!(s.fairness_modes.declared_tenant_count(), 0);
        assert_eq!(s.fairness_mode_for("any-tenant"), FairnessMode::Disabled);
        // Sem baseline instalado → metrics() retorna None.
        assert!(s.jonas_monitor.metrics("any-tenant").is_none());
        // Sem records → metrics() retorna None (consistente com ADR-0086).
        assert!(s.rawls_monitor.metrics("any-tenant").is_none());
    }

    #[tokio::test]
    async fn rawls_monitor_records_per_tenant_via_appstate() {
        let s = fresh_state();
        for _ in 0..40 {
            s.rawls_monitor
                .record("acme", GroupClass::Privileged, OutcomeBucket::Favorable);
            s.rawls_monitor
                .record("acme", GroupClass::Unprivileged, OutcomeBucket::Favorable);
        }
        let m = s.rawls_monitor.metrics("acme").expect("metrics installed");
        assert!(!m.violates_threshold);
        assert!(!m.insufficient_samples);
    }

    #[tokio::test]
    async fn jonas_monitor_install_and_record_via_appstate() {
        let s = fresh_state();
        let baseline_yaml = r#"
version: "1.0.0"
model_id: "test-model"
bins: 10
reference_proportions:
  - 0.05
  - 0.07
  - 0.10
  - 0.13
  - 0.15
  - 0.18
  - 0.15
  - 0.10
  - 0.05
  - 0.02
"#;
        let baseline = JonasBaselineLoader::from_yaml_str(baseline_yaml).expect("parse");
        s.jonas_monitor.install_baseline("acme", baseline);
        for _ in 0..600 {
            s.jonas_monitor.record("acme", 0.05, false);
        }
        // Após JONAS_COMPUTE_INTERVAL transações, metrics está populado.
        let m = s.jonas_monitor.metrics("acme").expect("metrics computed");
        assert!(m.psi.is_finite());
    }

    #[tokio::test]
    async fn fairness_mode_for_returns_disabled_unless_installed() {
        let s = fresh_state();
        assert_eq!(s.fairness_mode_for("ghost"), FairnessMode::Disabled);

        s.fairness_modes.install("acme", FairnessMode::Enforced);
        s.fairness_modes.install("globex-shadow", FairnessMode::Shadow);

        assert_eq!(s.fairness_mode_for("acme"), FairnessMode::Enforced);
        assert_eq!(s.fairness_mode_for("globex-shadow"), FairnessMode::Shadow);
        assert_eq!(s.fairness_mode_for("ghost"), FairnessMode::Disabled);
    }

    #[tokio::test]
    async fn monitors_isolate_tenants() {
        let s = fresh_state();
        // Tenant A: paridade.
        for _ in 0..40 {
            s.rawls_monitor
                .record("a", GroupClass::Privileged, OutcomeBucket::Favorable);
            s.rawls_monitor
                .record("a", GroupClass::Unprivileged, OutcomeBucket::Favorable);
        }
        // Tenant B: disparate impact severo.
        for _ in 0..40 {
            s.rawls_monitor
                .record("b", GroupClass::Privileged, OutcomeBucket::Favorable);
            s.rawls_monitor
                .record("b", GroupClass::Unprivileged, OutcomeBucket::Unfavorable);
        }
        let a = s.rawls_monitor.metrics("a").expect("a");
        let b = s.rawls_monitor.metrics("b").expect("b");
        assert!(!a.violates_threshold, "tenant a deve estar OK");
        assert!(b.violates_threshold, "tenant b deve violar");
    }
}
