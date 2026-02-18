"""
P6: Mercy Scenarios tests — 6 calibrated scenarios.
"""

import pytest
from buildtovalue.governance.mercy_scenarios import (
    evaluate_scenarios,
    downgrade_action,
    MercyScenarioResult,
)


class TestDowngradeAction:

    def test_block_minus_1(self):
        assert downgrade_action("BLOCK", 1) == "REDACT"

    def test_block_minus_2(self):
        assert downgrade_action("BLOCK", 2) == "EDUCATE"

    def test_redact_minus_1(self):
        assert downgrade_action("REDACT", 1) == "EDUCATE"

    def test_educate_minus_1(self):
        assert downgrade_action("EDUCATE", 1) == "LOG"

    def test_log_minus_1(self):
        assert downgrade_action("LOG", 1) == "ALLOW"

    def test_allow_floor(self):
        assert downgrade_action("ALLOW", 1) == "ALLOW"

    def test_block_minus_5_floors(self):
        assert downgrade_action("BLOCK", 5) == "ALLOW"


class TestS1CriticalOverride:

    def test_two_criticals_no_mercy(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.9, trust_score=0.9,
            finding_count=3, critical_count=2, composite_risk=0.7,
        )
        assert r.scenario_id == "S1_CRITICAL_OVERRIDE"
        assert r.downgrade_levels == 0
        assert r.final_action == "BLOCK"

    def test_extreme_risk_no_mercy(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.9, trust_score=0.9,
            finding_count=1, critical_count=0, composite_risk=0.95,
        )
        assert r.scenario_id == "S1_CRITICAL_OVERRIDE"
        assert not r.mercy_applied


class TestS2HighTrustVeteran:

    def test_trusted_first_offense_downgrade_2(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.8, trust_score=0.85,
            finding_count=2, critical_count=0, composite_risk=0.5,
            is_first_offense=True,
        )
        assert r.scenario_id == "S2_HIGH_TRUST_VETERAN"
        assert r.downgrade_levels == 2
        assert r.final_action == "EDUCATE"

    def test_trusted_but_has_critical_no_s2(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.8, trust_score=0.85,
            finding_count=2, critical_count=1, composite_risk=0.5,
            is_first_offense=True,
        )
        assert r.scenario_id != "S2_HIGH_TRUST_VETERAN"


class TestS3DomainContext:

    def test_medical_downgrade_1(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.6, trust_score=0.5,
            finding_count=2, critical_count=0, composite_risk=0.5,
            domain="medical",
        )
        assert r.scenario_id == "S3_DOMAIN_CONTEXT"
        assert r.downgrade_levels == 1
        assert r.final_action == "REDACT"

    def test_research_downgrade_1(self):
        r = evaluate_scenarios(
            action="REDACT", mercy_score=0.55, trust_score=0.4,
            finding_count=3, critical_count=0, composite_risk=0.4,
            domain="research",
        )
        assert r.scenario_id == "S3_DOMAIN_CONTEXT"
        assert r.final_action == "EDUCATE"

    def test_general_no_s3(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.6, trust_score=0.5,
            finding_count=2, critical_count=0, composite_risk=0.5,
            domain="general",
        )
        assert r.scenario_id != "S3_DOMAIN_CONTEXT"


class TestS4UncertainDetection:

    def test_low_findings_first_offense(self):
        r = evaluate_scenarios(
            action="EDUCATE", mercy_score=0.65, trust_score=0.4,
            finding_count=1, critical_count=0, composite_risk=0.3,
            domain="general", is_first_offense=True,
        )
        assert r.scenario_id == "S4_UNCERTAIN_DETECTION"
        assert r.downgrade_levels == 1
        assert r.final_action == "LOG"

    def test_many_findings_no_s4(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.65, trust_score=0.4,
            finding_count=5, critical_count=0, composite_risk=0.6,
            domain="general", is_first_offense=True,
        )
        assert r.scenario_id != "S4_UNCERTAIN_DETECTION"


class TestS5RepeatLeniency:

    def test_repeat_offender_with_trust(self):
        r = evaluate_scenarios(
            action="REDACT", mercy_score=0.55, trust_score=0.6,
            finding_count=3, critical_count=0, composite_risk=0.5,
            domain="general", is_first_offense=False,
        )
        assert r.scenario_id == "S5_REPEAT_LENIENCY"
        assert r.downgrade_levels == 1
        assert r.final_action == "EDUCATE"

    def test_repeat_low_trust_no_s5(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.55, trust_score=0.3,
            finding_count=3, critical_count=0, composite_risk=0.5,
            domain="general", is_first_offense=False,
        )
        assert r.scenario_id == "S6_DEFAULT_NO_MERCY"


class TestS6Default:

    def test_low_mercy_no_help(self):
        r = evaluate_scenarios(
            action="BLOCK", mercy_score=0.2, trust_score=0.3,
            finding_count=4, critical_count=0, composite_risk=0.7,
            domain="general", is_first_offense=False,
        )
        assert r.scenario_id == "S6_DEFAULT_NO_MERCY"
        assert r.downgrade_levels == 0
        assert r.final_action == "BLOCK"


class TestMercyNeverEscalates:
    """Mercy must NEVER make action MORE severe."""

    def test_mercy_never_escalates(self):
        for action in ["ALLOW", "LOG", "EDUCATE", "REDACT", "BLOCK"]:
            r = evaluate_scenarios(
                action=action, mercy_score=0.9, trust_score=0.9,
                finding_count=1, critical_count=0, composite_risk=0.3,
                is_first_offense=True,
            )
            from buildtovalue.governance.mercy_scenarios import ACTION_SEVERITY
            assert ACTION_SEVERITY[r.final_action] <= ACTION_SEVERITY[action], (
                f"Mercy escalated {action} → {r.final_action}"
            )