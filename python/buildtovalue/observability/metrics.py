"""
Prometheus metrics for Python Governance Layer.
Instrumenta decisões éticas, trust scores, appeals e ledger.
"""
from prometheus_client import Counter, Histogram, Gauge
import time
from contextlib import contextmanager
from typing import Optional

# ═══════════════════════════════════════════════════════════════
# Metrics Definitions
# ═══════════════════════════════════════════════════════════════

# Decisions
DECISIONS_TOTAL = Counter(
    "buildtovalue_decisions_total",
    "Total number of ethical decisions made",
    ["action", "profile"]
)

MERCY_APPLIED_TOTAL = Counter(
    "buildtovalue_mercy_applied_total",
    "Number of times mercy was applied",
    ["profile"]
)

# Latency
DECISION_DURATION_SECONDS = Histogram(
    "buildtovalue_decision_duration_seconds",
    "Decision-making duration",
    ["profile"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1]  # 1ms to 100ms
)

TRUST_SCORE_LOOKUP_DURATION_SECONDS = Histogram(
    "buildtovalue_trust_score_lookup_duration_seconds",
    "Trust score database lookup duration",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05]
)

# Trust Scores
TRUST_SCORE_DISTRIBUTION = Histogram(
    "buildtovalue_trust_score_distribution",
    "Distribution of trust scores",
    buckets=[0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
)

# Appeals
APPEALS_SUBMITTED_TOTAL = Counter(
    "buildtovalue_appeals_submitted_total",
    "Total appeals submitted",
    []
)

APPEALS_RESOLVED_TOTAL = Counter(
    "buildtovalue_appeals_resolved_total",
    "Total appeals resolved",
    ["outcome"]  # "ACCEPTED" or "REJECTED"
)

PENDING_APPEALS = Gauge(
    "buildtovalue_pending_appeals",
    "Number of appeals pending review"
)

# Ledger
LEDGER_WRITES_TOTAL = Counter(
    "buildtovalue_ledger_writes_total",
    "Total ledger writes",
    []
)

LEDGER_WRITE_DURATION_SECONDS = Histogram(
    "buildtovalue_ledger_write_duration_seconds",
    "Ledger write duration",
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1]
)

# System Health
ACTIVE_SESSIONS = Gauge(
    "buildtovalue_active_sessions",
    "Number of active user sessions"
)

SYSTEM_HEALTH_SCORE = Gauge(
    "buildtovalue_system_health_score",
    "Overall system health score (0.0-1.0)"
)

FALSE_POSITIVE_RATE = Gauge(
    "buildtovalue_false_positive_rate",
    "False positive rate from appeals",
    ["profile"]
)


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

@contextmanager
def measure_duration(histogram: Histogram, *labels):
    """
    Context manager to measure duration.

    Usage:
        with measure_duration(DECISION_DURATION_SECONDS, profile_name):
            # do work
    """
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        histogram.labels(*labels).observe(duration)


def record_decision(action: str, profile: str):
    """Record a decision."""
    DECISIONS_TOTAL.labels(action=action, profile=profile).inc()


def record_mercy(profile: str):
    """Record mercy applied."""
    MERCY_APPLIED_TOTAL.labels(profile=profile).inc()


def record_trust_score(score: float):
    """Record trust score."""
    TRUST_SCORE_DISTRIBUTION.observe(score)


def record_appeal_submitted():
    """Record appeal submission."""
    APPEALS_SUBMITTED_TOTAL.inc()
    PENDING_APPEALS.inc()


def record_appeal_resolved(outcome: str):
    """
    Record appeal resolution.

    Args:
        outcome: "ACCEPTED" or "REJECTED"
    """
    APPEALS_RESOLVED_TOTAL.labels(outcome=outcome).inc()
    PENDING_APPEALS.dec()


def record_ledger_write(duration: float):
    """Record ledger write."""
    LEDGER_WRITES_TOTAL.inc()
    LEDGER_WRITE_DURATION_SECONDS.observe(duration)


def update_active_sessions(count: int):
    """Update active sessions count."""
    ACTIVE_SESSIONS.set(count)


def update_system_health(score: float):
    """Update system health score (0.0-1.0)."""
    SYSTEM_HEALTH_SCORE.set(score)


def update_false_positive_rate(profile: str, rate: float):
    """
    Update false positive rate for profile.

    Args:
        profile: Profile name
        rate: False positive rate (0.0-1.0)
    """
    FALSE_POSITIVE_RATE.labels(profile=profile).set(rate)


# ═══════════════════════════════════════════════════════════════
# Instrumented Governance Layer
# ═══════════════════════════════════════════════════════════════

class InstrumentedGovernanceLayer:
    """
    Governance layer with metrics instrumentation.

    Example usage:
        governance = InstrumentedGovernanceLayer(
            trust_calculator=trust_calc,
            mercy_calculator=mercy_calc,
            profile_manager=profile_mgr
        )

        verdict = governance.decide(evidence, context, "general")
    """

    def __init__(self, trust_calculator, mercy_calculator, profile_manager):
        self.trust_calculator = trust_calculator
        self.mercy_calculator = mercy_calculator
        self.profile_manager = profile_manager

    def decide(self, evidence, context, profile_name: str):
        """
        Make ethical decision (with metrics).

        Args:
            evidence: TechnicalEvidence from Rust
            context: RequestMetadata
            profile_name: Profile name to apply

        Returns:
            EthicalVerdict
        """
        with measure_duration(DECISION_DURATION_SECONDS, profile_name):
            # Load profile
            profile = self.profile_manager.load_profile(profile_name)

            # Get trust score
            with measure_duration(TRUST_SCORE_LOOKUP_DURATION_SECONDS):
                trust_score = self.trust_calculator.calculate(
                    context.session_id, context.user_role
                )
            record_trust_score(trust_score)

            # Calculate mercy
            mercy_score = self.mercy_calculator.calculate(
                evidence=evidence,
                context=context.__dict__,
                trust_score=trust_score
            )

            # Make decision (simplified - integrate with EthicalContextEngine)
            verdict = self._make_decision(
                evidence, context, profile, trust_score, mercy_score
            )

            # Record metrics
            record_decision(verdict.action.name, profile_name)
            if verdict.mercy_score > 0.5:
                record_mercy(profile_name)

            # Record ledger write
            start = time.time()
            self._write_to_ledger(verdict)
            ledger_duration = time.time() - start
            record_ledger_write(ledger_duration)

            return verdict

    def _make_decision(self, evidence, context, profile, trust_score, mercy_score):
        """
        Placeholder for decision logic.
        In production: integrate with EthicalContextEngine.
        """
        # TODO: Integrate with real EthicalContextEngine
        pass

    def _write_to_ledger(self, verdict):
        """
        Placeholder for ledger write.
        In production: integrate with DurableLedger.
        """
        # TODO: Integrate with real Ledger
        pass


# ═══════════════════════════════════════════════════════════════
# Metrics Export
# ═══════════════════════════════════════════════════════════════

def start_metrics_server(port: int = 9090):
    """
    Start Prometheus metrics HTTP server.

    Args:
        port: Port to listen on (default: 9090)

    Usage:
        start_metrics_server(port=9090)
        # Metrics available at http://localhost:9090/metrics
    """
    from prometheus_client import start_http_server
    start_http_server(port)
    print(f"Prometheus metrics server started on port {port}")
