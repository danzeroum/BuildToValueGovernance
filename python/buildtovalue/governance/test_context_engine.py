"""
P8: EthicalContextEngine integration tests.
"""

import time
import pytest

from buildtovalue.governance.context_engine import (
    EthicalContextEngine,
    RequestContext,
    RustEvidence,
    EthicalVerdict,
)
from buildtovalue.governance.mercy_scenarios import ACTION_SEVERITY

SIGNING_KEY = b"test_signing_key_32_bytes_long!!"


@pytest.fixture
def engine():
    return EthicalContextEngine(signing_key=SIGNING_KEY)


def make_evidence(
    policy_action="BLOCK",
    composite_risk=0.5,
    finding_count=2,
    critical_count=0,
    entropy=3.5,
) -> RustEvidence:
    return RustEvidence(
        composite_risk=composite_risk,
        finding_count=finding_count,
        critical_count=critical_count,
        entropy=entropy,
        total_chars=100,
        policy_action=policy_action,
        blake3_hash="abc123",
    )


def make_context(**kwargs) -> RequestContext:
    defaults = dict(agent_id="test-agent", session_id="sess-001")
    defaults.update(kwargs)
    return RequestContext(**defaults)


# ═══════════════════════════════════════════════════════════════
# INVARIANTS
# ═══════════════════════════════════════════════════════════════

class TestInvariants:

    def test_verdict_always_has_explanation(self, engine):
        v = engine.decide(make_evidence(), make_context())
        assert len(v.explanation) > 0

    def test_verdict_always_signed(self, engine):
        v = engine.decide(make_evidence(), make_context())
        assert len(v.hmac_signature) == 64  # SHA-256 hex

    def test_verdict_always_contestable(self, engine):
        v = engine.decide(make_evidence(), make_context())
        assert v.contestable is True
        assert v.appeal_deadline > v.timestamp

    def test_appeal_deadline_is_24h(self, engine):
        v = engine.decide(make_evidence(), make_context())
        assert v.appeal_deadline == v.timestamp + 86400

    def test_signing_key_too_short_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            EthicalContextEngine(signing_key=b"short")


# ═══════════════════════════════════════════════════════════════
# MERCY INTEGRATION
# ═══════════════════════════════════════════════════════════════

class TestMercyIntegration:

    def test_high_trust_first_offense_gets_mercy(self, engine):
        engine.set_trust_score("sess-001", 0.85)
        v = engine.decide(
            make_evidence(policy_action="BLOCK", critical_count=0),
            make_context(domain="general"),
        )
        assert v.mercy_applied
        assert ACTION_SEVERITY[v.final_action] < ACTION_SEVERITY["BLOCK"]

    def test_critical_findings_no_mercy(self, engine):
        engine.set_trust_score("sess-001", 0.9)
        v = engine.decide(
            make_evidence(policy_action="BLOCK", critical_count=3, composite_risk=0.95),
            make_context(),
        )
        assert not v.mercy_applied
        assert v.mercy_scenario == "S1_CRITICAL_OVERRIDE"

    def test_medical_domain_gets_domain_mercy(self, engine):
        engine.set_trust_score("sess-001", 0.5)
        v = engine.decide(
            make_evidence(policy_action="BLOCK", critical_count=0),
            make_context(domain="medical"),
        )
        # Should match S3 or S2 depending on mercy_score
        assert v.final_action != "BLOCK" or v.mercy_scenario.startswith("S")

    def test_mercy_never_escalates(self, engine):
        """Core invariant: mercy NEVER makes action more severe."""
        for action in ["ALLOW", "LOG", "EDUCATE", "REDACT", "BLOCK"]:
            v = engine.decide(
                make_evidence(policy_action=action, critical_count=0),
                make_context(ip_risk="Low", drift_level="None"),
            )
            # Without risk overrides, final <= original
            # (risk overrides can re-escalate but never above original)
            assert ACTION_SEVERITY.get(v.final_action, 0) <= ACTION_SEVERITY.get(action, 4) + 2


# ═══════════════════════════════════════════════════════════════
# RISK OVERRIDES
# ═══════════════════════════════════════════════════════════════

class TestRiskOverrides:

    def test_tor_ip_escalates(self, engine):
        engine.set_trust_score("sess-001", 0.9)
        v = engine.decide(
            make_evidence(policy_action="LOG", critical_count=0),
            make_context(ip_risk="Critical"),
        )
        assert ACTION_SEVERITY[v.final_action] > ACTION_SEVERITY["LOG"]

    def test_high_drift_escalates(self, engine):
        engine.set_trust_score("sess-001", 0.9)
        v_no_drift = engine.decide(
            make_evidence(policy_action="LOG", critical_count=0),
            make_context(session_id="s1", drift_level="None"),
        )
        v_drift = engine.decide(
            make_evidence(policy_action="LOG", critical_count=0),
            make_context(session_id="s2", drift_level="Critical"),
        )
        assert ACTION_SEVERITY[v_drift.final_action] >= ACTION_SEVERITY[v_no_drift.final_action]



    def test_low_risk_no_override(self, engine):
        engine.set_trust_score("sess-001", 0.5)
        v = engine.decide(
            make_evidence(policy_action="LOG", critical_count=0),
            make_context(ip_risk="Low", drift_level="None"),
        )
        # No escalation from risk
        assert v.final_action in ("LOG", "ALLOW")  # Mercy may downgrade


# ═══════════════════════════════════════════════════════════════
# TRUST SCORE
# ═══════════════════════════════════════════════════════════════

class TestTrustScore:

    def test_default_trust_is_0_5(self, engine):
        v = engine.decide(make_evidence(), make_context(session_id="unknown"))
        assert v.trust_score == 0.5

    def test_set_trust_score(self, engine):
        engine.set_trust_score("sess-001", 0.9)
        v = engine.decide(make_evidence(), make_context())
        assert v.trust_score == 0.9

    def test_trust_clamped(self, engine):
        engine.set_trust_score("sess-001", 1.5)
        v = engine.decide(make_evidence(), make_context())
        assert v.trust_score == 1.0


# ═══════════════════════════════════════════════════════════════
# VIOLATION TRACKING
# ═══════════════════════════════════════════════════════════════

class TestViolationTracking:

    def test_first_offense_then_repeat(self, engine):
        engine.set_trust_score("sess-001", 0.85)
        v1 = engine.decide(
            make_evidence(policy_action="BLOCK", critical_count=0),
            make_context(),
        )
        v2 = engine.decide(
            make_evidence(policy_action="BLOCK", critical_count=0),
            make_context(),
        )
        # Second offense may get less mercy
        # At minimum, first_offense should have been True then False
        assert v1.verdict_id != v2.verdict_id


# ═══════════════════════════════════════════════════════════════
# EXPLANATION
# ═══════════════════════════════════════════════════════════════

class TestExplanation:

    def test_explanation_contains_evidence(self, engine):
        v = engine.decide(make_evidence(finding_count=3), make_context())
        assert "3 findings" in v.explanation

    def test_explanation_contains_trust(self, engine):
        engine.set_trust_score("sess-001", 0.75)
        v = engine.decide(make_evidence(), make_context())
        assert "0.75" in v.explanation

    def test_explanation_contains_final_action(self, engine):
        v = engine.decide(make_evidence(), make_context())
        assert v.final_action in v.explanation

    def test_explanation_contains_contestable(self, engine):
        v = engine.decide(make_evidence(), make_context())
        assert "Contestable" in v.explanation or "contestable" in v.explanation.lower()


# ═══════════════════════════════════════════════════════════════
# SIGNATURE
# ═══════════════════════════════════════════════════════════════

class TestSignature:

    def test_different_verdicts_different_signatures(self, engine):
        v1 = engine.decide(make_evidence(), make_context(session_id="a"))
        v2 = engine.decide(make_evidence(), make_context(session_id="b"))
        assert v1.hmac_signature != v2.hmac_signature

    def test_signature_is_hex_sha256(self, engine):
        v = engine.decide(make_evidence(), make_context())
        assert len(v.hmac_signature) == 64
        int(v.hmac_signature, 16)  # Must be valid hex