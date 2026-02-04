
"""
OpenTelemetry tracing for Python Governance Layer.

Integrates with Rust kernel via W3C Trace Context propagation.
"""

import os
import json
from typing import Optional, Dict, Any
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider, sampling
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.propagate import extract, inject, set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# ═══════════════════════════════════════════════════════════════
# Tracer Initialization
# ═══════════════════════════════════════════════════════════════

def init_tracer() -> trace.Tracer:
    """Initialize OpenTelemetry tracer"""
    
    # Resource (service metadata)
    resource = Resource(attributes={
        SERVICE_NAME: "buildtovalue-governance",
        SERVICE_VERSION: "2.0.0",
        "service.namespace": "buildtovalue",
        "deployment.environment": os.getenv("ENVIRONMENT", "development"),
    })
    
    # Sampler (10% sampling in production)
    sampler = sampling.ParentBasedTraceIdRatio(0.1)
    
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
    
    print("OpenTelemetry tracer initialized")
    
    return trace.get_tracer(__name__)

# Global tracer instance
tracer = init_tracer()

# ═══════════════════════════════════════════════════════════════
# Tracing Decorators
# ═══════════════════════════════════════════════════════════════

def trace_function(name: Optional[str] = None):
    """
    Decorator to automatically trace a function.
    
    Usage:
        @trace_function()
        def my_function(arg1, arg2):
            ...
    """
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            span_name = name or func.__name__
            
            with tracer.start_as_current_span(span_name) as span:
                # Record function arguments
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)
                
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("otel.status_code", "OK")
                    return result
                
                except Exception as e:
                    span.set_attribute("otel.status_code", "ERROR")
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
    
    Returns JSON string with W3C Trace Context headers.
    """
    carrier = {}
    inject(carrier)
    return json.dumps(carrier)

# ═══════════════════════════════════════════════════════════════
# Instrumented Governance Functions
# ═══════════════════════════════════════════════════════════════

from governance.decision_engine import EthicalContextEngine
from kernel_bindings.types import TechnicalEvidence

class InstrumentedEthicalContextEngine(EthicalContextEngine):
    """Ethical Context Engine with tracing instrumentation"""
    
    @trace_function("ethical_decision")
    def decide(
        self,
        evidence: TechnicalEvidence,
        context: Dict[str, Any],
        profile: Dict[str, Any],
    ):
        """Make ethical decision (with tracing)"""
        
        span = trace.get_current_span()
        
        # Record evidence attributes
        span.set_attribute("evidence.finding_count", evidence.finding_count)
        span.set_attribute("evidence.critical_count", evidence.critical_count)
        span.set_attribute("evidence.has_pii", evidence.has_pii)
        span.set_attribute("profile.name", profile["name"])
        
        # Step 1: Get trust score
        with trace_span("get_trust_score", {"session_id": context.get("session_id")}):
            trust_score = self._get_trust_score(context.get("session_id"))
            span.set_attribute("trust_score", trust_score)
        
        # Step 2: Calculate mercy
        with trace_span("calculate_mercy"):
            mercy_score = self.mercy_calculator.calculate(
                evidence=evidence,
                context=context,
                trust_score=trust_score,
            )
            span.set_attribute("mercy_score", mercy_score)
        
        # Step 3: Make decision
        with trace_span("make_decision"):
            verdict = self._make_decision(evidence, context, profile, trust_score, mercy_score)
            span.set_attribute("verdict.action", verdict.action)
            span.set_attribute("verdict.confidence", verdict.confidence)
        
        # Step 4: Log to ledger
        with trace_span("log_to_ledger"):
            self._log_to_ledger(verdict)
        
        return verdict

# ═══════════════════════════════════════════════════════════════
# Trace Visualization Helpers
# ═══════════════════════════════════════════════════════════════

def print_trace_context():
    """Print current trace context (for debugging)"""
    span = trace.get_current_span()
    ctx = span.get_span_context()
    
    if ctx.is_valid:
        print(f"Trace ID: {format(ctx.trace_id, '032x')}")
        print(f"Span ID:  {format(ctx.span_id, '016x')}")
        print(f"Trace Flags: {ctx.trace_flags}")
    else:
        print("No active trace context")