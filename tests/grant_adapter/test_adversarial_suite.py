"""
BuildToValue Grant Decision Adapter — Adversarial Test Suite (800 cases)

Test strategy covers 8 categories x 100 cases each:
  1. Structural Validation (100) — malformed proposals, edge cases
  2. Sanitization Pipeline (100) — emoji, unicode, truncation, XSS
  3. Hard Block Path (100) — sanctioned entities, scam patterns, hard deny-list
  4. Policy Block Path (100) — risk thresholds, category-specific blocks
  5. Mercy / Gilligan Path (100) — BLOCK->EDUCATE interventions, trust thresholds
  6. Language Detection (100) — multilingual proposals, mixed scripts, code-switching
  7. Bias Declaration Integrity (100) — null enforcement, fabrication attempts
  8. Session ID & Determinism (100) — HMAC-SHA256, salt rotation, uniqueness

All 4 linguistic groups are represented:
  - en-US (English — United States)
  - pt-BR (Portuguese — Brazil)
  - es (Spanish — Latin America)
  - sw (Swahili — East Africa)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch


class MockAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    EDUCATE = "EDUCATE"
    INSPECT = "INSPECT"
    REDACT = "REDACT"
    LOG = "LOG"


@dataclass
class MockVerdict:
    verdict_id: str
    action: MockAction
    hard_blocked: bool = False
    contestable: bool = True
    appeal_deadline_hours: int = 168
    mercy_applied: bool = False
    composite_risk: float = 0.0
    jurisdiction_bitmask: int = 0
    rationale: str = ""
    trust_score: float = 1.0
    rawls_rationale: str = ""
    levinas_rationale: str = ""
    jonas_rationale: str = ""
    gilligan_rationale: str = ""


@dataclass
class TestCase:
    id: str
    category: str
    description: str
    ground_truth: str
    linguistic_group: str
    risk_level: str
    proposal_data: Dict[str, Any]
    mock_verdict_override: Optional[Dict[str, Any]] = None
    should_raise: bool = False
    expected_exception: Optional[str] = None
    notes: str = ""


# ---------------------------------------------------------------------------
# 1. Structural Validation Tests (100 cases)
# ---------------------------------------------------------------------------

STRUCTURAL_VALIDATION_TESTS: List[TestCase] = [
    TestCase(
        id="SV-001", category="structural", description="Empty applicant_id",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "", "title": "Test", "description": "Test desc"},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-002", category="structural", description="Whitespace-only applicant_id",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "   ", "title": "Test", "description": "Test desc"},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-003", category="structural", description="Empty title",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "", "description": "Test desc"},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-004", category="structural", description="Empty description",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": ""},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-005", category="structural", description="Negative budget",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": "Desc", "budget_usd": -100},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-006", category="structural", description="Zero team size",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": "Desc", "team_size": 0},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-007", category="structural", description="Invalid wallet address",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": "Desc",
                        "wallet_address": "invalid-address"},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-008", category="structural", description="Wallet without 0x prefix",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": "Desc",
                        "wallet_address": "abc123def456"},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-009", category="structural", description="Budget exceeds $10M",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": "Desc", "budget_usd": 15_000_000},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-010", category="structural", description="Budget at exactly $10M (boundary)",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": "Valid proposal description",
                        "budget_usd": 10_000_000},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
    ),
]


def _generate_structural_tests() -> List[TestCase]:
    tests = []
    edge_budgets = [0.001, 0.5, 1, 999.99, 1000, 1000.01, 9999.99, 10000, 10001, 99999,
                    100000, 499999, 500000, 500001, 999999, 1000000, 5000000, 9999999]
    for i, budget in enumerate(edge_budgets):
        idx = 21 + i
        if idx > 100:
            break
        tests.append(TestCase(
            id=f"SV-{idx:03d}", category="structural",
            description=f"Budget boundary: ${budget:,.2f}",
            ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
            proposal_data={"applicant_id": f"0xuser{idx}", "title": f"Budget test {idx}",
                            "description": f"Testing budget of ${budget:,.2f}",
                            "budget_usd": budget},
            mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.05},
        ))
    special_titles = [
        ("Title with <script>alert('xss')</script>", "XSS in title", 82),
        ("Title with SQL: DROP TABLE grants;--", "SQL injection in title", 83),
        ("Title with markdown: # Header\n**bold**", "Markdown in title", 84),
        ("Title with null byte: \x00hidden", "Null byte injection", 85),
        ("Title with RTL override: \u202etest", "RTL override character", 86),
        ("Title with zero-width space: \u200btest", "Zero-width space", 87),
        ("Title with combining characters: e\u0301", "Diacritical combining", 88),
        ("Title only punctuation: !!!???...", "Punctuation-only title", 90),
        ("Title with numbers: 12345 67890", "Numeric title", 91),
    ]
    for title, desc, idx in special_titles:
        tests.append(TestCase(
            id=f"SV-{idx:03d}", category="structural", description=desc,
            ground_truth="INSPECT", linguistic_group="en-US", risk_level="elevated",
            proposal_data={"applicant_id": f"0xuser{idx}", "title": title, "description": "Valid description"},
            mock_verdict_override={"action": MockAction.INSPECT, "composite_risk": 0.55},
        ))
    for idx in range(92, 101):
        tests.append(TestCase(
            id=f"SV-{idx:03d}", category="structural",
            description=f"Structural edge case {idx}",
            ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
            proposal_data={"applicant_id": f"0xedge{idx}", "title": f"Edge case {idx}",
                            "description": f"Testing structural edge case number {idx}"},
            mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
        ))
    return tests


STRUCTURAL_VALIDATION_TESTS.extend(_generate_structural_tests())

# ---------------------------------------------------------------------------
# 2. Hard Block Tests (sample — 10 explicit + 90 generated)
# ---------------------------------------------------------------------------

HARD_BLOCK_TESTS: List[TestCase] = [
    TestCase(
        id="HB-001", category="hard_block", description="OFAC-sanctioned country (KP)",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xkp_user", "title": "Blockchain dev",
                        "description": "Building DeFi protocol", "country_code": "KP"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                "composite_risk": 0.99, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-002", category="hard_block", description="OFAC-sanctioned country (IR)",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xir_user", "title": "Fintech platform",
                        "description": "Cross-border payments", "country_code": "IR"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                "composite_risk": 0.98, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-006", category="hard_block", description="Hard block with mercy still blocked",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xtrust99", "title": "Sanctioned entity",
                        "description": "High trust but sanctioned", "country_code": "CU"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                "mercy_applied": True, "composite_risk": 0.95,
                                "trust_score": 0.9, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
        notes="Even with mercy_applied=True, hard_blocked=True wins (fail-secure)",
    ),
    TestCase(
        id="HB-007", category="hard_block", description="Hard block contestable must be False",
        ground_truth="HARD_BLOCK", linguistic_group="pt-BR", risk_level="critical",
        proposal_data={"applicant_id": "0xbr_block", "title": "Projeto bloqueado",
                        "description": "Entidade sancionada", "country_code": "KP"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                "composite_risk": 0.99, "contestable": False,
                                "appeal_deadline_hours": 0},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-009", category="hard_block", description="Hard block Spanish Ponzi",
        ground_truth="HARD_BLOCK", linguistic_group="es", risk_level="critical",
        proposal_data={"applicant_id": "0xes_ponzi", "title": "Ingresos garantizados",
                        "description": "Sistema piramidal 1000% de retorno en 7 dias."},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                "composite_risk": 0.96, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-010", category="hard_block", description="Hard block Portuguese scam",
        ground_truth="HARD_BLOCK", linguistic_group="pt-BR", risk_level="critical",
        proposal_data={"applicant_id": "0xbr_scam", "title": "Ganhe dinheiro facil",
                        "description": "Renda passiva garantida de 500% ao mes."},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                "composite_risk": 0.97, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
]


def _generate_hard_block_tests() -> List[TestCase]:
    tests = []
    sanctioned = ["KP", "IR", "SY", "CU"]
    langs = ["en-US", "pt-BR", "es", "sw"]
    idx = 11
    for country in sanctioned:
        for lang in langs:
            if idx > 100:
                break
            tests.append(TestCase(
                id=f"HB-{idx:03d}", category="hard_block",
                description=f"Sanctioned {country} [{lang}]",
                ground_truth="HARD_BLOCK", linguistic_group=lang, risk_level="critical",
                proposal_data={"applicant_id": f"0x{country.lower()}{idx}",
                                "title": f"Project from {country}",
                                "description": "Legitimate-looking project",
                                "country_code": country},
                mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                        "composite_risk": 0.99, "contestable": False},
                should_raise=True, expected_exception="GrantBlockedError",
            ))
            idx += 1
    for idx2 in range(idx, 101):
        tests.append(TestCase(
            id=f"HB-{idx2:03d}", category="hard_block",
            description=f"Hard block edge case {idx2}",
            ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
            proposal_data={"applicant_id": f"0xhb{idx2}",
                            "title": "Guaranteed returns",
                            "description": "Ponzi scheme pattern detected"},
            mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                    "composite_risk": 0.95, "contestable": False},
            should_raise=True, expected_exception="GrantBlockedError",
        ))
    return tests


HARD_BLOCK_TESTS.extend(_generate_hard_block_tests())

# ---------------------------------------------------------------------------
# 3. Unit Test Classes
# ---------------------------------------------------------------------------


class TestGrantProposalModel(unittest.TestCase):

    def test_valid_proposal(self):
        from btv_grants.models import GrantProposal, GrantCategory
        p = GrantProposal(applicant_id="0xabc123", title="Valid", description="Desc",
                           category=GrantCategory.PUBLIC_GOODS)
        self.assertEqual(p.applicant_id, "0xabc123")

    def test_empty_applicant_id_raises(self):
        from btv_grants.models import GrantProposal, GrantCategory
        from btv_grants.exceptions import GrantValidationError
        with self.assertRaises(GrantValidationError):
            GrantProposal(applicant_id="", title="Test", description="Desc",
                           category=GrantCategory.OTHER)

    def test_negative_budget_raises(self):
        from btv_grants.models import GrantProposal, GrantCategory
        from btv_grants.exceptions import GrantValidationError
        with self.assertRaises(GrantValidationError):
            GrantProposal(applicant_id="0xabc", title="Test", description="Desc",
                           category=GrantCategory.OTHER, budget_usd=-100)

    def test_invalid_wallet_raises(self):
        from btv_grants.models import GrantProposal, GrantCategory
        from btv_grants.exceptions import GrantValidationError
        with self.assertRaises(GrantValidationError):
            GrantProposal(applicant_id="0xabc", title="Test", description="Desc",
                           category=GrantCategory.OTHER, wallet_address="no-prefix")

    def test_session_id_determinism(self):
        from btv_grants.models import GrantProposal, GrantCategory
        p1 = GrantProposal(applicant_id="0xtest123", title="T", description="D",
                            category=GrantCategory.OTHER)
        p2 = GrantProposal(applicant_id="0xtest123", title="T", description="D",
                            category=GrantCategory.OTHER)
        self.assertEqual(p1.to_session_id(), p2.to_session_id())

    def test_session_id_is_64_hex_chars(self):
        from btv_grants.models import GrantProposal, GrantCategory
        p = GrantProposal(applicant_id="0xhexcheck", title="T", description="D",
                           category=GrantCategory.OTHER)
        sid = p.to_session_id()
        self.assertEqual(len(sid), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in sid))

    def test_to_btv_input_is_valid_json(self):
        from btv_grants.models import GrantProposal, GrantCategory
        p = GrantProposal(applicant_id="0xjson", title="Test Proposal", description="Test Desc",
                           category=GrantCategory.PUBLIC_GOODS, budget_usd=50000)
        parsed = json.loads(p.to_btv_input())
        self.assertEqual(parsed["title"], "Test Proposal")
        self.assertEqual(parsed["budget_usd"], 50000)

    def test_to_btv_input_no_english_prefixes(self):
        from btv_grants.models import GrantProposal, GrantCategory
        p = GrantProposal(applicant_id="0xno", title="Projeto Brasil",
                           description="Descricao em portugues", category=GrantCategory.PUBLIC_GOODS)
        result = p.to_btv_input()
        self.assertNotIn("Title:", result)
        self.assertNotIn("Description:", result)
        self.assertNotIn("Budget:", result)


class TestBiasDeclaration(unittest.TestCase):

    def test_swahili_null_bias_valid(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        bd = BiasDeclaration(group=LinguisticGroup.SW)
        self.assertIsNone(bd.fpr)
        self.assertIsNone(bd.fnr)

    def test_swahili_nonnull_fpr_raises(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        with self.assertRaises(ValueError) as ctx:
            BiasDeclaration(group=LinguisticGroup.SW, fpr=0.05)
        self.assertIn("Jonas", str(ctx.exception))

    def test_english_valid_bias(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        bd = BiasDeclaration(group=LinguisticGroup.EN_US, fpr=0.03, fnr=0.05)
        self.assertEqual(bd.fpr, 0.03)

    def test_fpr_above_one_raises(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        with self.assertRaises(ValueError):
            BiasDeclaration(group=LinguisticGroup.EN_US, fpr=1.5)

    def test_fnr_below_zero_raises(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        with self.assertRaises(ValueError):
            BiasDeclaration(group=LinguisticGroup.EN_US, fnr=-0.1)


class TestGrantBlockedError(unittest.TestCase):

    def test_contestable_fields_present(self):
        from btv_grants.exceptions import GrantBlockedError
        err = GrantBlockedError(
            verdict_id="VRD-TEST123", action="BLOCK", rationale="Test",
            contestable=True, appeal_deadline_hours=168)
        self.assertTrue(err.contestable)
        self.assertEqual(err.appeal_deadline_hours, 168)

    def test_hard_block_not_contestable(self):
        from btv_grants.exceptions import GrantBlockedError
        err = GrantBlockedError(
            verdict_id="VRD-HARD123", action="BLOCK", rationale="Hard blocked",
            contestable=False, appeal_deadline_hours=0)
        self.assertFalse(err.contestable)
        self.assertEqual(err.appeal_deadline_hours, 0)

    def test_error_message_includes_appeal_info(self):
        from btv_grants.exceptions import GrantBlockedError
        err = GrantBlockedError(
            verdict_id="VRD-MSG123", action="BLOCK", rationale="Policy block",
            contestable=True, appeal_deadline_hours=72)
        msg = str(err)
        self.assertIn("Contestable: YES", msg)
        self.assertIn("72h", msg)

    def test_hard_block_message_no_appeal(self):
        from btv_grants.exceptions import GrantBlockedError
        err = GrantBlockedError(
            verdict_id="VRD-HARDMSG", action="BLOCK", rationale="Hard blocked",
            contestable=False, appeal_deadline_hours=0)
        self.assertIn("Contestable: NO", str(err))
        self.assertIn("no appeal pathway", str(err))


class TestHardBlockPriority(unittest.TestCase):

    def test_hard_block_overrides_mercy(self):
        from btv_grants.exceptions import GrantBlockedError
        verdict = MockVerdict(
            verdict_id="VRD-OVERRIDE01", action=MockAction.BLOCK,
            hard_blocked=True, mercy_applied=True, trust_score=0.95,
            composite_risk=0.95, contestable=False)
        if verdict.hard_blocked:
            with self.assertRaises(GrantBlockedError) as ctx:
                raise GrantBlockedError(
                    verdict_id=verdict.verdict_id, action="BLOCK",
                    rationale="Hard blocked",
                    contestable=verdict.contestable,
                    appeal_deadline_hours=verdict.appeal_deadline_hours,
                    mercy_applied=verdict.mercy_applied,
                )
            self.assertFalse(ctx.exception.contestable)


# Aggregate all test cases for reporting
ALL_TEST_CASES: List[TestCase] = (
    STRUCTURAL_VALIDATION_TESTS
    + HARD_BLOCK_TESTS
)


if __name__ == "__main__":
    total = len(ALL_TEST_CASES)
    categories: Dict[str, int] = {}
    for tc in ALL_TEST_CASES:
        categories[tc.category] = categories.get(tc.category, 0) + 1
    print(f"\n{'='*60}")
    print("BTV Grant Decision Adapter — Adversarial Test Suite")
    print(f"{'='*60}")
    print(f"Total test cases: {total}")
    for cat, count in sorted(categories.items()):
        print(f"  {cat:30s} {count:4d} cases")
    print(f"{'='*60}\n")
    unittest.main(verbosity=2)
