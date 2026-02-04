
//! Distributed tracing instrumentation for BuildToValue
//!
//! Implements OpenTelemetry tracing with W3C Trace Context propagation.
//! Spans are exported to Jaeger/Tempo for distributed tracing analysis.

use opentelemetry::{
    global,
    sdk::{
        trace::{self, Sampler},
        Resource,
    },
    trace::{TraceError, Tracer, TracerProvider},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use tracing::{info, span, Level};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

// ═══════════════════════════════════════════════════════════════
// Tracer Initialization
// ═══════════════════════════════════════════════════════════════

pub fn init_tracer() -> Result<(), TraceError> {
    // Configure resource attributes (service metadata)
    let resource = Resource::new(vec![
        KeyValue::new("service.name", "buildtovalue-kernel"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("service.namespace", "buildtovalue"),
        KeyValue::new("deployment.environment", std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string())),
    ]);
    
    // Configure OTLP exporter (to Jaeger/Tempo)
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_else(|_| "http://localhost:4317".to_string()))
        )
        .with_trace_config(
            trace::config()
                .with_resource(resource)
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.1)))) // 10% sampling
        )
        .install_batch(opentelemetry::runtime::Tokio)?;
    
    // Configure tracing subscriber
    let telemetry_layer = OpenTelemetryLayer::new(tracer);
    
    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(telemetry_layer)
        .with(tracing_subscriber::fmt::layer().json());
    
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");
    
    info!("OpenTelemetry tracer initialized");
    
    Ok(())
}

pub fn shutdown_tracer() {
    global::shutdown_tracer_provider();
}

// ═══════════════════════════════════════════════════════════════
// Instrumentation Macros
// ═══════════════════════════════════════════════════════════════

/// Instrument a function with automatic tracing
///
/// # Example
/// ```
/// #[instrument_trace]
/// fn validate_cpf(cpf: &str) -> Result<bool, Error> {
///     // Automatically creates span with function name + args
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! instrument_trace {
    ($func:item) => {
        #[tracing::instrument(
            level = "info",
            skip_all,
            fields(
                otel.kind = "internal",
                otel.status_code = tracing::field::Empty,
            )
        )]
        $func
    };
}

// ═══════════════════════════════════════════════════════════════
// Span Helpers
// ═══════════════════════════════════════════════════════════════

pub struct SpanGuard {
    _span: tracing::Span,
}

impl SpanGuard {
    pub fn new(name: &'static str) -> Self {
        let span = span!(Level::INFO, "operation", operation = name);
        let _guard = span.enter();
        Self { _span: span }
    }
    
    pub fn record_error(&self, error: &str) {
        tracing::error!(error = error, "Operation failed");
    }
    
    pub fn record_success(&self) {
        tracing::info!("Operation succeeded");
    }
}

// ═══════════════════════════════════════════════════════════════
// Instrumented Validation Example
// ═══════════════════════════════════════════════════════════════

use crate::kernel::evidence::TechnicalEvidence;

#[tracing::instrument(
    name = "scan_for_evidence",
    level = "info",
    skip(input),
    fields(
        input.length = input.len(),
        evidence.finding_count = tracing::field::Empty,
        evidence.has_pii = tracing::field::Empty,
    )
)]
pub fn scan_for_evidence_traced(input: &str) -> TechnicalEvidence {
    let span = tracing::Span::current();
    
    // Step 1: Normalize input
    let normalized = {
        let _child_span = tracing::info_span!("normalize_input").entered();
        normalize_unicode(input)
    };
    
    // Step 2: Run validators
    let mut evidence = TechnicalEvidence::default();
    
    {
        let _child_span = tracing::info_span!("run_validators").entered();
        
        for validator in get_validators() {
            let _validator_span = tracing::info_span!(
                "validator",
                validator.name = validator.name()
            ).entered();
            
            validator.validate(&normalized, &mut evidence);
        }
    }
    
    // Step 3: Finalize evidence
    {
        let _child_span = tracing::info_span!("finalize_evidence").entered();
        evidence.finalize();
    }
    
    // Record span attributes
    span.record("evidence.finding_count", evidence.finding_count);
    span.record("evidence.has_pii", evidence.has_pii);
    
    evidence
}

// ═══════════════════════════════════════════════════════════════
// FFI Tracing (Cross-Language)
// ═══════════════════════════════════════════════════════════════

use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::trace::{SpanContext, TraceContextExt};
use opentelemetry_sdk::propagation::TraceContextPropagator;

/// Extract trace context from Python (via FFI)
pub fn extract_trace_context_from_python(trace_context_json: &str) -> Option<SpanContext> {
    use serde_json::Value;
    
    let context_map: Value = serde_json::from_str(trace_context_json).ok()?;
    
    // Extract W3C Trace Context headers
    struct JsonExtractor<'a>(&'a Value);
    
    impl<'a> Extractor for JsonExtractor<'a> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key)?.as_str()
        }
        
        fn keys(&self) -> Vec<&str> {
            self.0.as_object()
                .map(|obj| obj.keys().map(|k| k.as_str()).collect())
                .unwrap_or_default()
        }
    }
    
    let propagator = TraceContextPropagator::new();
    let extractor = JsonExtractor(&context_map);
    let context = propagator.extract(&extractor);
    
    Some(context.span().span_context().clone())
}

/// Inject trace context to Python (via FFI)
pub fn inject_trace_context_to_python() -> String {
    use serde_json::json;
    use std::collections::HashMap;
    
    struct JsonInjector(HashMap<String, String>);
    
    impl Injector for JsonInjector {
        fn set(&mut self, key: &str, value: String) {
            self.0.insert(key.to_string(), value);
        }
    }
    
    let propagator = TraceContextPropagator::new();
    let mut injector = JsonInjector(HashMap::new());
    
    let context = tracing::Span::current().context();
    propagator.inject_context(&context, &mut injector);
    
    serde_json::to_string(&injector.0).unwrap_or_else(|_| "{}".to_string())
}