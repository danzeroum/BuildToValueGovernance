"""
OpenTelemetry tracing integration for BuildToValue Governance.

Provides:
- TracerProvider setup with OTLP exporter
- trace_function decorator and trace_span context manager
- Rust-Python trace context propagation
- InstrumentedEthicalContextEngine wrapper

v2.3.1: Fixed broken imports.
  - Removed import from ffi_client (broken FFI with mock _deserialize_evidence).
  - EthicalContextEngine imported from canonical ethical_context_engine module.
  - EthicalVerdict imported from context_engine_types (where it is defined).
  - Type hints are lazy strings (from __future__ import annotations) so runtime
    duck-typing is preserved for evidence objects from any source.
"""
from __future__ import annotations
import functools
import json
import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Optional

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider, sampling
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.propagate import extract, inject, set_global_textmap
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# v2.3.1: Canonical engine path (ethical_context_engine.py = v1.1.0 unified).
from buildtovalue.governance.ethical_context_engine import EthicalContextEngine
# EthicalVerdict, RequestContext are defined in context_engine_types (not in the engine file).
from buildtovalue.governance.context_engine_types import (
    EthicalVerdict,
    RequestContext,
)
from buildtovalue.governance.types import RequestMetadata

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Tracer Initialization
# ═══════════════════════════════════════════════════════════════

def init_tracer(
        service_name: str = "buildtovalue-governance",
        service_version: str = "2.0.0",
        sampling_rate: float = 0.1
) -> trace.Tracer:
    """
    Initialize OpenTelemetry tracer.

    Args:
        service_name: Service name for telemetry
        service_version: Service version
        sampling_rate: Sampling rate (0.0-1.0, default 10%)

    Returns:
        Configured tracer instance
    """
    # Resource (service metadata)
    resource = Resource(attributes={
        SERVICE_NAME: service_name,
        SERVICE_VERSION: service_version,
        "service.namespace": "buildtovalue",
        "deployment.environment": os.getenv("ENVIRONMENT", "development"),
    })

    # Sampler (configurable sampling rate)
    sampler = sampling.ParentBasedTraceIdRatio(sampling_rate)

    # Tracer provider
    provider = TracerProvider(
        resource=resource,
        sampler=sampler,
    )

    # OTLP exporter
    otlp_exporter = OTLPSpanExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
        insecure=True,
    )

    # Batch span processor (async export)
    span_processor = BatchSpanProcessor(otlp_exporter)
    provider.add_span_processor(span_processor)

    # Set global provider
    trace.set_tracer_provider(provider)

    # Set global propagator (W3C Trace Context)
    set_global_textmap(TraceContextTextMapPropagator())

    print(f"OpenTelemetry tracer initialized: {service_name} v{service_version}")
    return trace.get_tracer(__name__)


# Global tracer instance
tracer = init_tracer()


# ═══════════════════════════════════════════════════════════════
# Tracing Decorators
# ═══════════════════════════════════════════════════════════════

def trace_function(name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
    """
    Decorator to automatically trace a function.

    Args:
        name: Span name (default: function name)
        attributes: Static attributes to add to span

    Usage:
        @trace_function("my_operation")
        def my_function(arg1, arg2):
            ...
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            span_name = name or func.__name__
            with tracer.start_as_current_span(span_name) as span:
                # Record function metadata
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)

                # Add static attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)

                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("otel.status_code", "OK")
                    return result
                except Exception as e:
                    span.set_attribute("otel.status_code", "ERROR")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    span.record_exception(e)
                    raise

        return wrapper

    return decorator


# ═══════════════════════════════════════════════════════════════
# Context Managers
# ═══════════════════════════════════════════════════════════════

@contextmanager
def trace_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """
    Context manager for manual span creation.

    Args:
        name: Span name
        attributes: Attributes to add to span

    Usage:
        with trace_span("my_operation", {"key": "value"}):
            # do work
    """
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        yield span


# ═══════════════════════════════════════════════════════════════
# Rust-Python Trace Context Propagation
# ═══════════════════════════════════════════════════════════════

def extract_trace_context_from_rust(trace_context_json: str) -> trace.SpanContext:
    """
    Extract trace context from Rust kernel (via FFI).

    The Rust kernel sends trace context as JSON:
    {
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        "tracestate": "..."
    }

    Args:
        trace_context_json: JSON string with trace context

    Returns:
        Extracted SpanContext
    """
    context_dict = json.loads(trace_context_json)

    # Use W3C Trace Context propagator to extract
    from opentelemetry.context import Context
    carrier = context_dict
    context = extract(carrier)

    return trace.get_current_span(context).get_span_context()


def inject_trace_context_to_rust() -> str:
    """
    Inject trace context to Rust kernel (via FFI).

    Returns:
        JSON string with W3C Trace Context headers

    Example output:
    {
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    }
    """
    carrier = {}
    inject(carrier)
    return json.dumps(carrier)


# ═══════════════════════════════════════════════════════════════
# Instrumented Governance Functions
# ═══════════════════════════════════════════════════════════════

class InstrumentedEthicalContextEngine(EthicalContextEngine):
    """
    Ethical Context Engine with tracing instrumentation.

    CORRIGIDO: Usa métodos reais da classe pai.
    """

    @trace_function("ethical_decision")
    def decide(
            self,
            evidence: Any,
            context: RequestMetadata,
            profile_name: str,
    ) -> EthicalVerdict:
        """
        Make ethical decision (with tracing).

        Args:
            evidence: Technical evidence from Rust
            context: Request metadata
            profile_name: Profile name to apply

        Returns:
            EthicalVerdict
        """
        span = trace.get_current_span()

        # Record evidence attributes
        span.set_attribute("evidence.protocol_version", evidence.protocol_version)
        span.set_attribute("evidence.finding_count", evidence.finding_count)
        span.set_attribute("evidence.critical_count", evidence.critical_count)
        span.set_attribute("evidence.composite_risk", evidence.composite_risk)
        span.set_attribute("evidence.input_size", evidence.input_size)
        span.set_attribute("evidence.processing_time_us", evidence.processing_time_us)

        # Record stats
        span.set_attribute("evidence.entropy", evidence.stats.entropy)
        span.set_attribute("evidence.zscore", evidence.stats.zscore)
        span.set_attribute("evidence.has_pii", evidence.stats.has_pii)
        span.set_attribute("evidence.has_sensitive_data", evidence.stats.has_sensitive_data)

        # Record context attributes
        span.set_attribute("context.agent_id", context.agent_id)
        span.set_attribute("context.session_id", context.session_id)
        span.set_attribute("context.user_role", context.user_role)
        span.set_attribute("context.domain", context.domain)
        span.set_attribute("profile.name", profile_name)

        # Step 1: Get trust score (traced automatically by parent method)
        with trace_span("trust_score_calculation", {
            "session_id": context.session_id,
            "user_role": context.user_role
        }):
            trust_score = self.trust_calculator.calculate(
                context.session_id, context.user_role
            )
            span.set_attribute("trust_score", trust_score)

        # Step 2: Calculate mercy (traced automatically)
        with trace_span("mercy_calculation"):
            mercy_score = self.mercy_calculator.calculate(
                evidence=evidence,
                context=context.__dict__,
                trust_score=trust_score
            )
            span.set_attribute("mercy_score", mercy_score)

        # Step 3: Make decision (calls parent method - CORRIGIDO)
        with trace_span("decision_logic"):
            verdict = super().decide(evidence, context, profile_name)

        # Record verdict attributes
        span.set_attribute("verdict.action", verdict.action.name)
        span.set_attribute("verdict.confidence", verdict.confidence)
        span.set_attribute("verdict.mercy_score", verdict.mercy_score)
        span.set_attribute("verdict.trust_score", verdict.trust_score)
        if verdict.rule_id:
            span.set_attribute("verdict.rule_id", verdict.rule_id)

        # Record decision factors
        if verdict.context_factors:
            for key, value in verdict.context_factors.items():
                span.set_attribute(f"decision_factor.{key}", value)

        return verdict


# ═══════════════════════════════════════════════════════════════
# Trace Visualization Helpers
# ═══════════════════════════════════════════════════════════════

def print_trace_context():
    """
    Print current trace context (for debugging).

    Output:
        Trace ID: 0af7651916cd43dd8448eb211c80319c
        Span ID: b7ad6b7169203331
        Trace Flags: 01
    """
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx.is_valid:
        print(f"Trace ID: {format(ctx.trace_id, '032x')}")
        print(f"Span ID: {format(ctx.span_id, '016x')}")
        print(f"Trace Flags: {ctx.trace_flags:02x}")
    else:
        print("No active trace context")


def get_trace_id() -> Optional[str]:
    """
    Get current trace ID (for logging correlation).

    Returns:
        Trace ID as hex string, or None if no active trace
    """
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx.is_valid:
        return format(ctx.trace_id, '032x')
    return None


def get_span_id() -> Optional[str]:
    """
    Get current span ID.

    Returns:
        Span ID as hex string, or None if no active span
    """
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx.is_valid:
        return format(ctx.span_id, '016x')
    return None


# ═══════════════════════════════════════════════════════════════
# Example Usage
# ═══════════════════════════════════════════════════════════════

"""
Example usage:

    # Initialize tracer
    tracer = init_tracer("my-service", "1.0.0", sampling_rate=0.1)

    # Use decorator
    @trace_function("my_operation")
    def process_data(data):
        # do work
        return result

    # Use context manager
    with trace_span("database_query", {"query_type": "SELECT"}):
        results = db.query("SELECT * FROM users")

    # Use instrumented engine
    engine = InstrumentedEthicalContextEngine(
        trust_calculator=trust_calc,
        mercy_calculator=mercy_calc,
        profile_manager=profile_mgr
    )
    verdict = engine.decide(evidence, context, "general")

    # Get trace ID for logging
    trace_id = get_trace_id()
    logger.info("Decision made", extra={"trace_id": trace_id})
"""
