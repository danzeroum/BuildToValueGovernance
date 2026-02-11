//! Distributed tracing instrumentation for BuildToValue
//!
//! **REQUIRES FEATURE**: `observability`
//!
//! Compile with: `cargo build --features observability`

// ═══════════════════════════════════════════════════════════════════════════
// CONDITIONAL COMPILATION - Só existe se feature estiver ativa
// ═══════════════════════════════════════════════════════════════════════════
#![cfg(feature = "observability")]

use opentelemetry::{global, KeyValue};
use opentelemetry_sdk::{trace as sdktrace, Resource};
use opentelemetry::trace::TraceError;
use opentelemetry_otlp::WithExportConfig;
use tracing::{info, span, Level};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

// ═══════════════════════════════════════════════════════════════════════════
// Tracer Initialization
// ═══════════════════════════════════════════════════════════════════════════

pub fn init_tracer() -> Result<(), TraceError> {
    let resource = Resource::new(vec![
        KeyValue::new("service.name", "buildtovalue-kernel"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("service.namespace", "buildtovalue"),
        KeyValue::new(
            "deployment.environment",
            std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
        ),
    ]);

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(
                    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                        .unwrap_or_else(|_| "http://localhost:4317".to_string()),
                ),
        )
        .with_trace_config(
            sdktrace::Config::default()
                .with_resource(resource)
                .with_sampler(sdktrace::Sampler::ParentBased(Box::new(
                    sdktrace::Sampler::TraceIdRatioBased(0.1),
                ))),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

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

// ═══════════════════════════════════════════════════════════════════════════
// Span Helpers
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// FFI Tracing
// ═══════════════════════════════════════════════════════════════════════════

use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::trace::{SpanContext, TraceContextExt};
use opentelemetry_sdk::propagation::TraceContextPropagator;

pub fn extract_trace_context_from_python(trace_context_json: &str) -> Option<SpanContext> {
    use serde_json::Value;

    let context_map: Value = serde_json::from_str(trace_context_json).ok()?;

    struct JsonExtractor<'a>(&'a Value);

    impl<'a> Extractor for JsonExtractor<'a> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key)?.as_str()
        }

        fn keys(&self) -> Vec<&str> {
            self.0
                .as_object()
                .map(|obj| obj.keys().map(|k| k.as_str()).collect())
                .unwrap_or_default()
        }
    }

    let propagator = TraceContextPropagator::new();
    let extractor = JsonExtractor(&context_map);
    let context = propagator.extract(&extractor);

    Some(context.span().span_context().clone())
}

pub fn inject_trace_context_to_python() -> String {
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