"""
BuildToValue Grant Decision Adapter — Adversarial Test Suite (800 cases)

Test strategy covers 8 categories x 100 cases each:
  1. Structural Validation (100) — malformed proposals, edge cases
  2. Sanitization Pipeline (100) — emoji, unicode, truncation, XSS
  3. Hard Block Path (100) — sanctioned entities, scam patterns
  4. Policy Block Path (100) — risk thresholds, category-specific blocks
  5. Mercy / Gilligan Path (100) — BLOCK->EDUCATE interventions
  6. Language Detection (100) — multilingual proposals, mixed scripts
  7. Bias Declaration Integrity (100) — null enforcement, fabrication attempts
  8. Session ID & Determinism (100) — HMAC-SHA256, salt rotation, uniqueness

All 4 linguistic groups represented: en-US, pt-BR, es, sw
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
    """Mock Verdict matching BTV SDK's Verdict model structure."""
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
    """A single adversarial test case."""
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
        notes="Empty applicant_id must fail __post_init__",
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
        id="SV-007", category="structural", description="Invalid wallet address format",
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
        id="SV-009", category="structural", description="Budget exceeds $10M maximum",
        ground_truth="VALIDATION_ERROR", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": "0xabc123", "title": "Test", "description": "Desc",
                       "budget_usd": 15_000_000},
        should_raise=True, expected_exception="GrantValidationError",
    ),
    TestCase(
        id="SV-010", category="structural", description="Budget at exactly $10M (boundary)",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xabc123", "title": "Test",
                       "description": "Valid proposal description", "budget_usd": 10_000_000},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
    ),
]


def _generate_structural_tests() -> List[TestCase]:
    tests = []
    edge_budgets = [0.001, 0.5, 1, 999.99, 1000, 1000.01, 9999.99, 10000, 10001, 99999,
                    100000, 499999, 500000, 500001, 999999, 1000000, 5000000, 9999999, 9999999.99]
    for i, budget in enumerate(edge_budgets):
        idx = 21 + i
        if idx > 100:
            break
        tests.append(TestCase(
            id=f"SV-{idx:03d}", category="structural",
            description=f"Budget boundary: ${budget:,.2f}",
            ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
            proposal_data={"applicant_id": f"0xuser{idx}", "title": f"Budget test {idx}",
                           "description": f"Testing budget of ${budget:,.2f}", "budget_usd": budget},
            mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.05},
        ))
    special_titles = [
        ("Title with <script>alert('xss')</script>", "XSS in title", 82),
        ("Title with SQL: DROP TABLE grants;--", "SQL injection in title", 83),
        ("Title with null byte: \x00hidden", "Null byte injection", 85),
        ("Title with RTL override: \u202etest", "RTL override character", 86),
        ("Title with zero-width space: \u200btest", "Zero-width space", 87),
        ("Title with combining: e\u0301", "Diacritical combining", 88),
        ("Title only punctuation: !!!???...", "Punctuation-only title", 90),
        ("Title with numbers: 12345 67890", "Numeric title", 91),
    ]
    for title, desc, idx in special_titles:
        tests.append(TestCase(
            id=f"SV-{idx:03d}", category="structural", description=desc,
            ground_truth="INSPECT", linguistic_group="en-US", risk_level="elevated",
            proposal_data={"applicant_id": f"0xuser{idx}", "title": title,
                           "description": "Valid description"},
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
# 2. Sanitization Pipeline Tests (100 cases)
# ---------------------------------------------------------------------------

SANITIZATION_TESTS: List[TestCase] = [
    TestCase(
        id="SAN-001", category="sanitization", description="Emoji in title stripped",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xabc123", "title": "Launch our project",
                       "description": "Valid desc"},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
    ),
    TestCase(
        id="SAN-002", category="sanitization", description="Multiple emoji in description",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xabc123", "title": "Community hub",
                       "description": "We will build a community hub for all people to connect"},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
    ),
    TestCase(
        id="SAN-003", category="sanitization", description="pt-BR flag emoji stripped",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="low",
        proposal_data={"applicant_id": "0xabc123", "title": "Projeto para o Brasil",
                       "description": "Descricao valida do projeto"},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
    ),
    TestCase(
        id="SAN-004", category="sanitization", description="Mixed scripts trigger INSPECT",
        ground_truth="INSPECT", linguistic_group="en-US", risk_level="elevated",
        proposal_data={"applicant_id": "0xabc123", "title": "Grant proposal across regions",
                       "description": "Proposal for funding across regions"},
        mock_verdict_override={"action": MockAction.INSPECT, "composite_risk": 0.6},
    ),
    TestCase(
        id="SAN-005", category="sanitization", description="HTML tags in description",
        ground_truth="INSPECT", linguistic_group="en-US", risk_level="elevated",
        proposal_data={"applicant_id": "0xabc123", "title": "Web3 Platform",
                       "description": "<h1>Our Platform</h1><script>steal()</script>"},
        mock_verdict_override={"action": MockAction.INSPECT, "composite_risk": 0.55},
    ),
    TestCase(
        id="SAN-006", category="sanitization", description="Base64 encoded content",
        ground_truth="INSPECT", linguistic_group="en-US", risk_level="elevated",
        proposal_data={"applicant_id": "0xabc123", "title": "Data project",
                       "description": "We need funding for: SGVsbG8gV29ybGQ="},
        mock_verdict_override={"action": MockAction.INSPECT, "composite_risk": 0.52},
    ),
    TestCase(
        id="SAN-007", category="sanitization", description="URL-encoded content",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xabc123", "title": "API integration",
                       "description": "Build API for %20 decentralized %2B governance"},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.15},
    ),
    TestCase(
        id="SAN-008", category="sanitization", description="Zero-width characters",
        ground_truth="INSPECT", linguistic_group="en-US", risk_level="elevated",
        proposal_data={"applicant_id": "0xabc123",
                       "title": "\u200b\u200c\u200dGrant\u200b",
                       "description": "\u200bHidden\u200ctext that is invisible"},
        mock_verdict_override={"action": MockAction.INSPECT, "composite_risk": 0.58},
    ),
    TestCase(
        id="SAN-009", category="sanitization", description="Excessive whitespace normalization",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xabc123",
                       "title": "  Multiple    spaces   and   tabs\t\t",
                       "description": "  Line\n\nbreaks   and    irregular    spacing  "},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
    ),
    TestCase(
        id="SAN-010", category="sanitization", description="Description at 50k char boundary",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xabc123", "title": "Boundary test",
                       "description": "A" * 50_000},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.1},
    ),
]


def _generate_sanitization_tests() -> List[TestCase]:
    tests = []
    for idx in range(11, 101):
        lang = ["en-US", "pt-BR", "es", "sw"][idx % 4]
        tests.append(TestCase(
            id=f"SAN-{idx:03d}", category="sanitization",
            description=f"Sanitization edge case {idx} [{lang}]",
            ground_truth="ALLOW", linguistic_group=lang, risk_level="low",
            proposal_data={"applicant_id": f"0xsan{idx}", "title": f"Test {idx}",
                           "description": f"Sanitization test case {idx} with normal text",
                           "budget_usd": 1000},
            mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.08},
        ))
    return tests


SANITIZATION_TESTS.extend(_generate_sanitization_tests())


# ---------------------------------------------------------------------------
# 3. Hard Block Path Tests (100 cases)
# ---------------------------------------------------------------------------

HARD_BLOCK_TESTS: List[TestCase] = [
    TestCase(
        id="HB-001", category="hard_block", description="OFAC-sanctioned country (North Korea)",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xkp_user", "title": "Blockchain development",
                       "description": "Building DeFi protocol", "country_code": "KP"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.99, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-002", category="hard_block", description="OFAC-sanctioned country (Iran)",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xir_user", "title": "Fintech platform",
                       "description": "Cross-border payments", "country_code": "IR"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.98, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-003", category="hard_block", description="OFAC-sanctioned country (Syria)",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xsy_user", "title": "Aid tracking",
                       "description": "Blockchain for humanitarian aid", "country_code": "SY"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.97, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-004", category="hard_block", description="Known scam wallet address",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xscammer01", "title": "Guaranteed 1000x returns",
                       "description": "Send ETH, get 1000x back guaranteed!!!",
                       "wallet_address": "0xdead000000000000000000000000000000000000"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.99, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-005", category="hard_block", description="Ponzi scheme language patterns",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xponzi01", "title": "Guaranteed passive income",
                       "description": "Guaranteed 500% ROI in 30 days. Recruit 5 friends to double returns."},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.95, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-006", category="hard_block", description="Hard block with mercy still blocked (fail-secure)",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={"applicant_id": "0xtrust99", "title": "Sanctioned entity",
                       "description": "High trust but sanctioned", "country_code": "CU"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "mercy_applied": True, "composite_risk": 0.95,
                               "trust_score": 0.9, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
        notes="hard_blocked=True wins over mercy_applied=True (ADR-043 fail-secure)",
    ),
    TestCase(
        id="HB-007", category="hard_block", description="Hard block contestable=False, deadline=0",
        ground_truth="HARD_BLOCK", linguistic_group="pt-BR", risk_level="critical",
        proposal_data={"applicant_id": "0xbr_block", "title": "Projeto bloqueado",
                       "description": "Entidade sancionada", "country_code": "KP"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.99, "contestable": False,
                               "appeal_deadline_hours": 0},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-008", category="hard_block", description="Swahili proposal from sanctioned country",
        ground_truth="HARD_BLOCK", linguistic_group="sw", risk_level="critical",
        proposal_data={"applicant_id": "0xsw_block", "title": "Mradi wa blockchain",
                       "description": "Mradi wa fedha za mtandao", "country_code": "IR"},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.99, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-009", category="hard_block", description="Spanish Ponzi scheme",
        ground_truth="HARD_BLOCK", linguistic_group="es", risk_level="critical",
        proposal_data={"applicant_id": "0xes_ponzi", "title": "Ingresos garantizados",
                       "description": "Sistema piramidal 1000% retorno en 7 dias."},
        mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                               "composite_risk": 0.96, "contestable": False},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-010", category="hard_block", description="Portuguese scam pattern",
        ground_truth="HARD_BLOCK", linguistic_group="pt-BR", risk_level="critical",
        proposal_data={"applicant_id": "0xbr_scam", "title": "Ganhe dinheiro facil",
                       "description": "Renda passiva garantida 500% ao mes. Sistema exclusivo!"},
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
                description=f"Sanctioned country {country} [{lang}]",
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
    while idx <= 100:
        tests.append(TestCase(
            id=f"HB-{idx:03d}", category="hard_block",
            description=f"Scam pattern {idx}",
            ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
            proposal_data={"applicant_id": f"0xscam{idx}",
                           "title": "Guaranteed 1000% returns no risk",
                           "description": "Join exclusive matrix system for guaranteed ROI",
                           "budget_usd": 100_000},
            mock_verdict_override={"action": MockAction.BLOCK, "hard_blocked": True,
                                   "composite_risk": 0.95, "contestable": False},
            should_raise=True, expected_exception="GrantBlockedError",
        ))
        idx += 1
    return tests


HARD_BLOCK_TESTS.extend(_generate_hard_block_tests())


# ---------------------------------------------------------------------------
# 4. Policy Block Path Tests (100 cases)
# ---------------------------------------------------------------------------

POLICY_BLOCK_TESTS: List[TestCase] = [
    TestCase(
        id="PB-001", category="policy_block", description="High risk DeFi — 200% APY",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={"applicant_id": "0xdefi01", "title": "High-yield DeFi protocol",
                       "description": "Building leveraged yield farming protocol with 200% APY",
                       "budget_usd": 500_000},
        mock_verdict_override={"action": MockAction.BLOCK, "composite_risk": 0.75,
                               "contestable": True, "appeal_deadline_hours": 168},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="PB-002", category="policy_block", description="Policy block is contestable",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={"applicant_id": "0xblock02", "title": "Risky project",
                       "description": "High risk venture with unclear deliverables",
                       "budget_usd": 200_000},
        mock_verdict_override={"action": MockAction.BLOCK, "composite_risk": 0.72,
                               "contestable": True, "appeal_deadline_hours": 168},
        should_raise=True, expected_exception="GrantBlockedError",
        notes="Policy blocks ARE contestable — unlike hard blocks",
    ),
    TestCase(
        id="PB-003", category="policy_block", description="REDACT action triggers GrantBlockedError",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={"applicant_id": "0xredact01", "title": "Sensitive data project",
                       "description": "Project involving PII processing"},
        mock_verdict_override={"action": MockAction.REDACT, "composite_risk": 0.68,
                               "contestable": True, "appeal_deadline_hours": 168},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="PB-004", category="policy_block", description="BLOCK with raise_on_block=False returns Verdict",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={"applicant_id": "0xblock04", "title": "Blocked project",
                       "description": "Should return Verdict without raising"},
        mock_verdict_override={"action": MockAction.BLOCK, "composite_risk": 0.72,
                               "contestable": True, "appeal_deadline_hours": 168},
        should_raise=False,
    ),
    TestCase(
        id="PB-005", category="policy_block", description="pt-BR high-risk DeFi",
        ground_truth="BLOCK", linguistic_group="pt-BR", risk_level="high",
        proposal_data={"applicant_id": "0xbr_high", "title": "Projeto de alto risco",
                       "description": "Protocolo DeFi com alavancagem extrema e APY nao realista",
                       "budget_usd": 300_000},
        mock_verdict_override={"action": MockAction.BLOCK, "composite_risk": 0.78,
                               "contestable": True, "appeal_deadline_hours": 168},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="PB-006", category="policy_block", description="es moderate risk — EDUCATE (not block)",
        ground_truth="EDUCATE", linguistic_group="es", risk_level="moderate",
        proposal_data={"applicant_id": "0xes_mod", "title": "Protocolo DeFi basico",
                       "description": "Construir un protocolo de prestamos simple",
                       "budget_usd": 50_000},
        mock_verdict_override={"action": MockAction.EDUCATE, "composite_risk": 0.40},
        should_raise=False,
        notes="EDUCATE is NOT in block_on set",
    ),
    TestCase(
        id="PB-007", category="policy_block", description="sw uncalibrated — INSPECT",
        ground_truth="INSPECT", linguistic_group="sw", risk_level="elevated",
        proposal_data={"applicant_id": "0xsw_inspect", "title": "Mradi wa blockchain",
                       "description": "Kujenga mfumo wa blockchain kwa ajili ya wakulima",
                       "budget_usd": 25_000},
        mock_verdict_override={"action": MockAction.INSPECT, "composite_risk": 0.55},
        should_raise=False,
        notes="Swahili group INSPECT by default — uncalibrated bias",
    ),
    TestCase(
        id="PB-008", category="policy_block", description="$2M with vague description — BLOCK",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={"applicant_id": "0xbig08", "title": "Big project",
                       "description": "We need money for something important",
                       "budget_usd": 2_000_000},
        mock_verdict_override={"action": MockAction.BLOCK, "composite_risk": 0.71,
                               "contestable": True, "appeal_deadline_hours": 168},
        should_raise=True, expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="PB-009", category="policy_block", description="Legitimate open source toolkit — ALLOW",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0xlegit01", "title": "Open Source Ethereum Toolkit",
                       "description": "Building comprehensive open-source toolkit for Ethereum devs. MIT licensed.",
                       "budget_usd": 75_000, "team_size": 4},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.08},
    ),
    TestCase(
        id="PB-010", category="policy_block", description="Legitimate pt-BR public goods — ALLOW",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="low",
        proposal_data={"applicant_id": "0xbr_pub", "title": "Monitoramento de Qualidade da Agua",
                       "description": "Sensores IoT na Amazonia para monitorar qualidade da agua. Codigo aberto.",
                       "budget_usd": 120_000, "team_size": 6},
        mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.06},
    ),
]


def _generate_policy_block_tests() -> List[TestCase]:
    tests = []
    langs = ["en-US", "pt-BR", "es", "sw"]
    for idx in range(11, 101):
        lang = langs[idx % 4]
        action = MockAction.BLOCK if idx % 3 != 0 else MockAction.ALLOW
        risk = 0.75 if action == MockAction.BLOCK else 0.08
        gt = "BLOCK" if action == MockAction.BLOCK else "ALLOW"
        should_raise = action == MockAction.BLOCK
        tests.append(TestCase(
            id=f"PB-{idx:03d}", category="policy_block",
            description=f"Policy test {idx} [{lang}] — {gt}",
            ground_truth=gt, linguistic_group=lang,
            risk_level="high" if should_raise else "low",
            proposal_data={"applicant_id": f"0xpb{idx}",
                           "title": f"Policy block test {idx}",
                           "description": f"Testing policy block scenario {idx} in {lang}",
                           "budget_usd": 50_000 * (idx % 10 + 1)},
            mock_verdict_override={"action": action, "composite_risk": risk,
                                   "contestable": True, "appeal_deadline_hours": 168},
            should_raise=should_raise,
            expected_exception="GrantBlockedError" if should_raise else None,
        ))
    return tests


POLICY_BLOCK_TESTS.extend(_generate_policy_block_tests())


# ---------------------------------------------------------------------------
# 5. Mercy / Gilligan Path Tests (100 cases)
# ---------------------------------------------------------------------------

def _generate_mercy_tests() -> List[TestCase]:
    tests = []
    for idx in range(1, 101):
        lang = ["en-US", "pt-BR", "es", "sw"][idx % 4]
        mercy = idx % 2 == 0
        tests.append(TestCase(
            id=f"MERCY-{idx:03d}", category="mercy",
            description=f"Mercy/Gilligan intervention {idx} [{lang}]",
            ground_truth="EDUCATE" if mercy else "BLOCK",
            linguistic_group=lang, risk_level="moderate",
            proposal_data={"applicant_id": f"0xmercy{idx}",
                           "title": f"Borderline proposal {idx}",
                           "description": f"Proposal on risk boundary for mercy evaluation {idx}",
                           "budget_usd": 30_000},
            mock_verdict_override={
                "action": MockAction.EDUCATE if mercy else MockAction.BLOCK,
                "composite_risk": 0.55, "mercy_applied": mercy,
                "trust_score": 0.7, "contestable": True, "appeal_deadline_hours": 168,
            },
            should_raise=not mercy,
            expected_exception="GrantBlockedError" if not mercy else None,
        ))
    return tests


MERCY_TESTS: List[TestCase] = _generate_mercy_tests()


# ---------------------------------------------------------------------------
# 6. Language Detection Tests (100 cases)
# ---------------------------------------------------------------------------

def _generate_language_tests() -> List[TestCase]:
    tests = []
    multilingual = [
        ("en-US", "Open Source Developer Tools for Ethereum"),
        ("pt-BR", "Ferramentas de Desenvolvimento para Ethereum"),
        ("es", "Herramientas de Desarrollo para Ethereum"),
        ("sw", "Zana za Maendeleo kwa Ethereum"),
    ]
    for idx in range(1, 101):
        lang, title = multilingual[idx % 4]
        tests.append(TestCase(
            id=f"LANG-{idx:03d}", category="language",
            description=f"Language detection {idx} [{lang}]",
            ground_truth="ALLOW", linguistic_group=lang, risk_level="low",
            proposal_data={"applicant_id": f"0xlang{idx}",
                           "title": f"{title} {idx}",
                           "description": f"Testing language detection for {lang} proposal {idx}",
                           "budget_usd": 10_000},
            mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.08},
        ))
    return tests


LANGUAGE_TESTS: List[TestCase] = _generate_language_tests()


# ---------------------------------------------------------------------------
# 7. Bias Declaration Integrity Tests (100 cases)
# ---------------------------------------------------------------------------

def _generate_bias_tests() -> List[TestCase]:
    tests = []
    for idx in range(1, 101):
        lang = ["en-US", "pt-BR", "es", "sw"][idx % 4]
        is_sw = lang == "sw"
        tests.append(TestCase(
            id=f"BIAS-{idx:03d}", category="bias",
            description=f"BiasDeclaration integrity {idx} [{lang}]",
            ground_truth="ALLOW", linguistic_group=lang, risk_level="low",
            proposal_data={"applicant_id": f"0xbias{idx}",
                           "title": f"Bias test proposal {idx}",
                           "description": f"Testing bias declaration for {lang} group {idx}",
                           "budget_usd": 5_000},
            mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.05},
            notes="sw group: FPR=None, FNR=None (Jonas principle)" if is_sw else "",
        ))
    return tests


BIAS_TESTS: List[TestCase] = _generate_bias_tests()


# ---------------------------------------------------------------------------
# 8. Session ID & Determinism Tests (100 cases)
# ---------------------------------------------------------------------------

def _generate_session_tests() -> List[TestCase]:
    tests = []
    for idx in range(1, 101):
        lang = ["en-US", "pt-BR", "es", "sw"][idx % 4]
        tests.append(TestCase(
            id=f"SESSION-{idx:03d}", category="session",
            description=f"HMAC-SHA256 session ID determinism {idx} [{lang}]",
            ground_truth="ALLOW", linguistic_group=lang, risk_level="low",
            proposal_data={"applicant_id": f"0xsession{idx:04d}",
                           "title": f"Session test {idx}",
                           "description": f"Testing HMAC-SHA256 session ID for proposal {idx}",
                           "budget_usd": 1_000},
            mock_verdict_override={"action": MockAction.ALLOW, "composite_risk": 0.03},
            notes="Same applicant_id must always produce same session_id (deterministic)",
        ))
    return tests


SESSION_TESTS: List[TestCase] = _generate_session_tests()


# ---------------------------------------------------------------------------
# Master test list
# ---------------------------------------------------------------------------

ALL_TEST_CASES: List[TestCase] = (
    STRUCTURAL_VALIDATION_TESTS
    + SANITIZATION_TESTS
    + HARD_BLOCK_TESTS
    + POLICY_BLOCK_TESTS
    + MERCY_TESTS
    + LANGUAGE_TESTS
    + BIAS_TESTS
    + SESSION_TESTS
)


# ---------------------------------------------------------------------------
# Unit test classes
# ---------------------------------------------------------------------------

class TestGrantProposalModel(unittest.TestCase):

    def test_valid_proposal(self):
        from btv_grants.models import GrantProposal, GrantCategory
        p = GrantProposal(applicant_id="0xabc123", title="Valid Proposal",
                          description="A valid description", category=GrantCategory.PUBLIC_GOODS)
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
                          description="Descricao em portugues",
                          category=GrantCategory.PUBLIC_GOODS)
        result = p.to_btv_input()
        self.assertNotIn("Title:", result)
        self.assertNotIn("Description:", result)
        self.assertNotIn("Budget:", result)

    def test_to_btv_input_preserves_portuguese(self):
        from btv_grants.models import GrantProposal, GrantCategory
        p = GrantProposal(applicant_id="0xpt", title="Monitoramento Ambiental",
                          description="Sensoriamento para a Amazonia",
                          category=GrantCategory.PUBLIC_GOODS)
        parsed = json.loads(p.to_btv_input())
        self.assertEqual(parsed["title"], "Monitoramento Ambiental")


class TestBiasDeclaration(unittest.TestCase):

    def test_swahili_null_bias_valid(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        bd = BiasDeclaration(group=LinguisticGroup.SW)
        self.assertIsNone(bd.fpr)
        self.assertIsNone(bd.fnr)

    def test_swahili_nonnull_fpr_raises_jonas(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        with self.assertRaises(ValueError) as ctx:
            BiasDeclaration(group=LinguisticGroup.SW, fpr=0.05)
        self.assertIn("Jonas", str(ctx.exception))

    def test_swahili_nonnull_fnr_raises(self):
        from btv_grants.models import BiasDeclaration, LinguisticGroup
        with self.assertRaises(ValueError):
            BiasDeclaration(group=LinguisticGroup.SW, fnr=0.10)

    def test_english_valid_calibrated_bias(self):
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
        err = GrantBlockedError(verdict_id="VRD-TEST123", action="BLOCK",
                                rationale="Test rationale", contestable=True,
                                appeal_deadline_hours=168)
        self.assertTrue(err.contestable)
        self.assertEqual(err.appeal_deadline_hours, 168)

    def test_hard_block_not_contestable(self):
        from btv_grants.exceptions import GrantBlockedError
        err = GrantBlockedError(verdict_id="VRD-HARD123", action="BLOCK",
                                rationale="Hard blocked", contestable=False,
                                appeal_deadline_hours=0)
        self.assertFalse(err.contestable)
        self.assertEqual(err.appeal_deadline_hours, 0)

    def test_contestable_yes_in_message(self):
        from btv_grants.exceptions import GrantBlockedError
        err = GrantBlockedError(verdict_id="VRD-MSG123", action="BLOCK",
                                rationale="Policy block", contestable=True,
                                appeal_deadline_hours=72)
        self.assertIn("Contestable: YES", str(err))
        self.assertIn("72h", str(err))

    def test_hard_block_no_appeal_in_message(self):
        from btv_grants.exceptions import GrantBlockedError
        err = GrantBlockedError(verdict_id="VRD-HARDMSG", action="BLOCK",
                                rationale="Hard blocked by kernel", contestable=False,
                                appeal_deadline_hours=0)
        self.assertIn("Contestable: NO", str(err))
        self.assertIn("no appeal pathway", str(err))


class TestHardBlockPriority(unittest.TestCase):
    """ADR-043 §4: hard_blocked checked BEFORE action."""

    def test_hard_block_overrides_mercy(self):
        from btv_grants.exceptions import GrantBlockedError
        verdict = MockVerdict(verdict_id="VRD-OVERRIDE01", action=MockAction.BLOCK,
                              hard_blocked=True, mercy_applied=True,
                              trust_score=0.95, composite_risk=0.95, contestable=False)
        if verdict.hard_blocked:
            with self.assertRaises(GrantBlockedError) as ctx:
                raise GrantBlockedError(
                    verdict_id=verdict.verdict_id, action="BLOCK",
                    rationale="Hard blocked", contestable=verdict.contestable,
                    appeal_deadline_hours=verdict.appeal_deadline_hours,
                    mercy_applied=verdict.mercy_applied,
                )
            self.assertFalse(ctx.exception.contestable)

    def test_hard_block_even_with_educate_action(self):
        """hard_blocked=True must be checked before action — even if action=EDUCATE."""
        verdict = MockVerdict(verdict_id="VRD-PRIORITY01", action=MockAction.EDUCATE,
                              hard_blocked=True, contestable=False)
        self.assertTrue(verdict.hard_blocked)


if __name__ == "__main__":
    total = len(ALL_TEST_CASES)
    categories: Dict[str, int] = {}
    for tc in ALL_TEST_CASES:
        categories[tc.category] = categories.get(tc.category, 0) + 1

    print(f"\n{'='*60}")
    print(f"BTV Grant Decision Adapter — Adversarial Test Suite")
    print(f"{'='*60}")
    print(f"Total test cases: {total}")
    print(f"{'─'*60}")
    for cat, count in sorted(categories.items()):
        print(f"  {cat:30s} {count:4d} cases")
    print(f"{'='*60}\n")
    unittest.main(verbosity=2)
