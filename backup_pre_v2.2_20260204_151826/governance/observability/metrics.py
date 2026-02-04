
"""
Prometheus metrics for Python Governance Layer
"""

from prometheus_client import Counter, Histogram, Gauge, Info
import time
from contextlib import contextmanager

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
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
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
    ["outcome"]  # "UPHOLD" or "OVERTURN"
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

# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

@contextmanager
def measure_duration(histogram, *labels):
    """Context manager to measure duration"""
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        histogram.labels(*labels).observe(duration)

def record_decision(action: str, profile: str):
    """Record a decision"""
    DECISIONS_TOTAL.labels(action=action, profile=profile).inc()

def record_mercy(profile: str):
    """Record mercy applied"""
    MERCY_APPLIED_TOTAL.labels(profile=profile).inc()

def record_trust_score(score: float):
    """Record trust score"""
    TRUST_SCORE_DISTRIBUTION.observe(score)

def record_appeal_submitted():
    """Record appeal submission"""
    APPEALS_SUBMITTED_TOTAL.inc()

def record_appeal_resolved(outcome: str):
    """Record appeal resolution"""
    APPEALS_RESOLVED_TOTAL.labels(outcome=outcome).inc()

def record_ledger_write(duration: float):
    """Record ledger write"""
    LEDGER_WRITES_TOTAL.inc()
    LEDGER_WRITE_DURATION_SECONDS.observe(duration)

# ═══════════════════════════════════════════════════════════════
# Instrumented Governance Layer
# ═══════════════════════════════════════════════════════════════

class InstrumentedGovernanceLayer:
    """Governance layer with metrics instrumentation"""
    
    def decide(self, evidence, context, profile):
        """Make ethical decision (with metrics)"""
        
        with measure_duration(DECISION_DURATION_SECONDS, profile["name"]):
            # Get trust score
            with measure_duration(TRUST_SCORE_LOOKUP_DURATION_SECONDS):
                trust_score = self._get_trust_score(context["session_id"])
            
            record_trust_score(trust_score)
            
            # Make decision
            verdict = self._make_decision(evidence, context, profile, trust_score)
            
            # Record metrics
            record_decision(verdict.action, profile["name"])
            
            if verdict.mercy_applied:
                record_mercy(profile["name"])
        
        return verdict