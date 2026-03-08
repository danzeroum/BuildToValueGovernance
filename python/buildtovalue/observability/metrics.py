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

# ═══════════════════════════════════════════════════════════════
# ADR-041: Métricas da República Algorítmica
# Pipeline filosófico por estágio + BiasGuardian + SLA + Trust
# ═══════════════════════════════════════════════════════════════

from prometheus_client import Summary

# ── Judiciário: pipeline por estágio filosófico ───────────────

PIPELINE_STAGE_DURATION = Histogram(
    "btv_pipeline_stage_duration_seconds",
    "Duração de cada estágio filosófico do pipeline ético",
    ["stage"],  # rawls | levinas | jonas | gilligan
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05]
)

RAWLS_ANOMALIES_TOTAL = Counter(
    "btv_rawls_anomalies_total",
    "Anomalias de equidade detectadas pelo estágio Rawls (blind test divergência)"
)

LEVINAS_CARE_OVERRIDES_TOTAL = Counter(
    "btv_levinas_care_overrides_total",
    "Decisões suavizadas pelo dever de cuidado (Levinas) — BLOCK→EDUCATE"
)

JONAS_RISK_ESCALATIONS_TOTAL = Counter(
    "btv_jonas_risk_escalations_total",
    "Escalações de risco pelo princípio de responsabilidade (Jonas)",
    ["reason"]  # ip_risk | bias_expired | critical_finding
)

JONAS_BIAS_EXPIRED_TOTAL = Counter(
    "btv_jonas_bias_expired_total",
    "BiasDeclarations expiradas detectadas pelo estágio Jonas (> 90 dias)"
)

GILLIGAN_SCENARIOS_TOTAL = Counter(
    "btv_gilligan_scenarios_total",
    "Cenários de misericórdia avaliados pelo estágio Gilligan",
    ["scenario"]  # S1_FIRST_OFFENSE | S2_HIGH_TRUST_VETERAN | S3_LOW_RISK | S4_CRITICAL_BLOCK | S5_EXPIRED_BIAS | S6_UNCERTAINTY
)

# ── Auditivo: SLA compliance appeals ─────────────────────────

APPEAL_SLA_COMPLIANCE = Gauge(
    "btv_appeal_sla_compliance_rate",
    "Taxa de appeals resolvidos dentro do SLA de 24h (0.0-1.0)"
)

APPEAL_SLA_BREACHES_TOTAL = Counter(
    "btv_appeal_sla_breaches_total",
    "Total de appeals que expiraram sem resolução (breach de SLA)"
)

APPEAL_TRUST_ADJUSTMENTS_TOTAL = Counter(
    "btv_appeal_trust_adjustments_total",
    "Ajustes de trust score via appeals",
    ["direction"]  # increment | decrement
)

# ── Legislativo: BiasGuardian divergência ─────────────────────

BIAS_FNR_DIVERGENCE = Gauge(
    "btv_bias_fnr_divergence_pct",
    "Divergência entre FNR declarado e medido em pontos percentuais",
    ["validator_id"]
)

BIAS_FPR_DIVERGENCE = Gauge(
    "btv_bias_fpr_divergence_pct",
    "Divergência entre FPR declarado e medido em pontos percentuais",
    ["validator_id"]
)

BIAS_GATE_STATUS = Gauge(
    "btv_bias_gate_status",
    "Status do gate de viés: 1=OK, 0=WARNING, -1=BLOCK ou inacessível",
    ["validator_id"]
)

# ── Trust Score v2.0 (ADR-039) ────────────────────────────────

TRUST_SCORE_ADJUSTMENTS_TOTAL = Counter(
    "btv_trust_score_adjustments_total",
    "Ajustes de trust score por tipo",
    ["type"]  # appeal_accepted | appeal_rejected | decay | violation
)

TRUST_SCORE_CURRENT = Gauge(
    "btv_trust_score_current",
    "Trust score atual por sessão (amostragem — não expõe session_id real)",
    ["bucket"]  # low_0_0.3 | medium_0.3_0.6 | high_0.6_1.0
)


# ═══════════════════════════════════════════════════════════════
# Helpers ADR-041
# ═══════════════════════════════════════════════════════════════

from contextlib import contextmanager

@contextmanager
def measure_pipeline_stage(stage: str):
    """Mede duração de estágio filosófico. Uso: with measure_pipeline_stage('rawls'): ..."""
    import time
    start = time.perf_counter()
    try:
        yield
    finally:
        PIPELINE_STAGE_DURATION.labels(stage=stage).observe(time.perf_counter() - start)


def record_bias_evaluation(validator_id: str, declared_fnr: float, measured_fnr: float,
                            declared_fpr: float, measured_fpr: float) -> str:
    """
    Registra resultado de avaliação BiasGuardian.
    Retorna nível: 'OK' | 'WARNING' | 'BLOCK'.
    Thresholds ADR-036: warning=5pp, block=15pp (FNR).
    """
    fnr_div = abs(measured_fnr - declared_fnr)
    fpr_div = abs(measured_fpr - declared_fpr)

    BIAS_FNR_DIVERGENCE.labels(validator_id=validator_id).set(fnr_div)
    BIAS_FPR_DIVERGENCE.labels(validator_id=validator_id).set(fpr_div)

    if fnr_div >= 15.0:
        level = "BLOCK"
        BIAS_GATE_STATUS.labels(validator_id=validator_id).set(-1)
    elif fnr_div >= 5.0:
        level = "WARNING"
        BIAS_GATE_STATUS.labels(validator_id=validator_id).set(0)
    else:
        level = "OK"
        BIAS_GATE_STATUS.labels(validator_id=validator_id).set(1)

    return level


def record_trust_bucket(score: float):
    """Registra trust score em bucket (privacy-preserving — sem session_id)."""
    if score < 0.3:
        bucket = "low_0_0.3"
    elif score < 0.6:
        bucket = "medium_0.3_0.6"
    else:
        bucket = "high_0.6_1.0"
    TRUST_SCORE_CURRENT.labels(bucket=bucket).set(score)


def record_sla_compliance(total_resolved: int, within_sla: int):
    """Atualiza gauge de SLA compliance após cada resolução ou expiração."""
    rate = within_sla / total_resolved if total_resolved > 0 else 1.0
    APPEAL_SLA_COMPLIANCE.set(rate)

# ── Over-refusal calibration (ADR-041 + Art.104/168) ─────────
# Proxy: trust > 0.7 AND mercy_scenario S1-S3 AND action != ALLOW

BENIGN_REFUSAL_TOTAL = Counter(
    "btv_benign_refusal_total",
    "Requisicoes provavelmente benignas que receberam BLOCK ou EDUCATE "
    "(trust > 0.7 AND mercy_scenario IN S1-S3 AND action != ALLOW)",
    ["action", "mercy_scenario", "domain"],
)

BENIGN_REFUSAL_RATE = Gauge(
    "btv_benign_refusal_rate",
    "Taxa movel (ultima hora) de recusas em requisicoes potencialmente benignas",
)

# -- Action Graph Observability (ADR-041) --
from prometheus_client import Counter, Histogram, Gauge

ACTION_TRANSITION_TOTAL = Counter(
    "btv_action_transition_total",
    "Transicoes de acao entre requests consecutivos na mesma sessao",
    ["from_action", "to_action"],
)

ACTION_SEQUENCE_ESCALATION_TOTAL = Counter(
    "btv_action_sequence_escalation_total",
    "Sequencias que escalaram severidade (ex: ALLOW->BLOCK)",
    ["pattern"],
)

ACTION_SEQUENCE_DEPTH = Histogram(
    "btv_action_sequence_depth",
    "Numero de requests por sessao antes de atingir BLOCK",
    buckets=[1, 2, 3, 5, 8, 13, 21],
)
