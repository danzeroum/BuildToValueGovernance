"""
Testes unitários — PolicyTester / Rawls Blind Testing (ADR-042).
Sem gateway real: mock do httpx.Client.
"""

import pytest
from unittest.mock import patch, MagicMock
from buildtovalue.governance.policy_tester import (
    PolicyTester,
    BlindTestCase,
    TestCategory,
    SYNTHETIC_DATASET,
)


@pytest.fixture
def tester():
    return PolicyTester(gateway_url="http://localhost:8080")


def _mock_response(action: str, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {"action": action}
    return resp


class TestDataset:

    def test_dataset_deterministic(self, tester):
        cases1 = tester._build_cases(seed=42)
        cases2 = tester._build_cases(seed=42)
        assert [c.case_id for c in cases1] == [c.case_id for c in cases2]

    def test_dataset_different_seeds(self, tester):
        cases1 = tester._build_cases(seed=42)
        cases2 = tester._build_cases(seed=99)
        assert [c.case_id for c in cases1] != [c.case_id for c in cases2]

    def test_covers_all_categories(self, tester):
        cases = tester._build_cases(seed=42)
        cats = {c.category for c in cases}
        assert TestCategory.HARD_BLOCK in cats
        assert TestCategory.BENIGN_TECHNICAL in cats
        assert TestCategory.INSTRUCTION_OVERRIDE in cats

    def test_dataset_size(self):
        assert len(SYNTHETIC_DATASET) >= 15


class TestEquity:

    def test_equity_pass_when_fpr_equal(self, tester):
        cases = tester._build_cases(seed=42)
        # Todos passam — FPR=0 para todos os grupos
        results = []
        for c in cases:
            from buildtovalue.governance.policy_tester import TestResult
            results.append(TestResult(
                case_id=c.case_id, category=c.category,
                expected_action=c.expected_action,
                actual_action=c.expected_action,
                passed=True, latency_ms=1.0, group=c.group,
            ))
        ok, details = tester._check_equity(cases, results)
        assert ok is True
        assert details["max_divergence"] <= 0.10

    def test_actions_compatible_educate_log(self, tester):
        assert tester._actions_compatible("EDUCATE", "LOG") is True
        assert tester._actions_compatible("LOG", "EDUCATE") is True
        assert tester._actions_compatible("BLOCK", "ALLOW") is False


class TestCIGate:

    def test_ci_gate_passes_with_all_correct(self, tester):
        cases = tester._build_cases(seed=42)
        from buildtovalue.governance.policy_tester import TestResult
        results = [
            TestResult(
                case_id=c.case_id, category=c.category,
                expected_action=c.expected_action,
                actual_action=c.expected_action,
                passed=True, latency_ms=1.0, group=c.group,
            )
            for c in cases
        ]
        report = tester._build_report("test", "epoch-1", cases, results, 100.0)
        assert report.pass_rate == 1.0
        assert report.ci_gate_passed is True

    def test_ci_gate_fails_below_95pct(self, tester):
        cases = tester._build_cases(seed=42)
        from buildtovalue.governance.policy_tester import TestResult
        results = [
            TestResult(
                case_id=c.case_id, category=c.category,
                expected_action=c.expected_action,
                actual_action="BLOCK" if i < 5 else c.expected_action,
                passed=i >= 5, latency_ms=1.0, group=c.group,
            )
            for i, c in enumerate(cases)
        ]
        report = tester._build_report("test", "epoch-1", cases, results, 100.0)
        assert report.pass_rate < 0.95
        assert report.ci_gate_passed is False
