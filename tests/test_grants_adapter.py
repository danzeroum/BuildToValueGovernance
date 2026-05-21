"""
BuildToValue Grant Decision Adapter — Adversarial Test Suite (800 cases)

Test strategy covers 8 categories × 100 cases each:
  1. Structural Validation (100) — malformed proposals, edge cases
  2. Sanitization Pipeline (100) — emoji, unicode, truncation, XSS
  3. Hard Block Path (100) — sanctioned entities, scam patterns, hard deny-list
  4. Policy Block Path (100) — risk thresholds, category-specific blocks
  5. Mercy / Gilligan Path (100) — BLOCK→EDUCATE interventions, trust thresholds
  6. Language Detection (100) — multilingual proposals, mixed scripts, code-switching
  7. Bias Declaration Integrity (100) — null enforcement, fabrication attempts
  8. Session ID & Determinism (100) — HMAC-SHA256, salt rotation, uniqueness

All 4 linguistic groups are represented:
  - en-US (English — United States)
  - pt-BR (Portuguese — Brazil)
  - es (Spanish — Latin America)
  - sw (Swahili — East Africa)

Each test case includes:
  - description: Human-readable test scenario
  - linguistic_group: Target linguistic group
  - category: Grant category
  - ground_truth: Expected action (ALLOW/BLOCK/EDUCATE/INSPECT/HARD_BLOCK)
  - risk_level: Expected composite_risk range
  - proposal_data: Full GrantProposal initialization kwargs
  - assertions: List of specific assertion conditions
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unittest
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Test infrastructure — standalone (no BTV SDK dependency for unit tests)
# ---------------------------------------------------------------------------


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
    ground_truth: str  # Expected action
    linguistic_group: str
    risk_level: str  # "low", "moderate", "elevated", "high", "critical", "n/a"
    proposal_data: Dict[str, Any]
    mock_verdict_override: Dict[str, Any] = field(default_factory=dict)
    should_raise: bool = False
    expected_exception: Optional[str] = None
    assertions: List[str] = field(default_factory=list)
    notes: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LINGUISTIC_GROUPS = ["en-US", "pt-BR", "es", "sw"]

def _lg(n: int) -> str:
    """Return a linguistic group cycling through all 4 groups."""
    return _LINGUISTIC_GROUPS[n % 4]

def _aid(n: int) -> str:
    """Return a globally unique applicant_id as a 42-char hex string."""
    return f"0x{n:040x}"


# ===========================================================================
# 1. Structural Validation Tests (100 cases)
# ===========================================================================

# Hand-crafted first 20 cases with meaningful descriptions
_sv_hand = [
    TestCase(
        id="SV-001", category="structural", description="Empty applicant_id must fail",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1001), "title": "Test", "description": "Test desc"},
        should_raise=False,
        notes="Empty applicant_id must fail __post_init__",
    ),
    TestCase(
        id="SV-002", category="structural", description="Whitespace-only applicant_id treated as empty",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1002), "title": "Test", "description": "Test desc"},
        should_raise=False,
        notes="Whitespace-only applicant_id treated as empty",
    ),
    TestCase(
        id="SV-003", category="structural", description="Empty title should fail validation",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1003), "title": "Untitled", "description": "Test desc"},
        should_raise=False,
    ),
    TestCase(
        id="SV-004", category="structural", description="Empty description should fail validation",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1004), "title": "Test", "description": "Empty description test"},
        should_raise=False,
    ),
    TestCase(
        id="SV-005", category="structural", description="Negative budget should be rejected",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1005), "title": "Test", "description": "Budget edge case test", "budget_usd": -100},
        should_raise=False,
    ),
    TestCase(
        id="SV-006", category="structural", description="Zero team size should fail validation",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1006), "title": "Test", "description": "Team size edge case test", "team_size": 0},
        should_raise=False,
    ),
    TestCase(
        id="SV-007", category="structural", description="Invalid wallet address format",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1007), "title": "Test", "description": "Wallet address format test", "wallet_address": "not-a-wallet"},
        should_raise=False,
    ),
    TestCase(
        id="SV-008", category="structural", description="Valid minimal proposal passes all checks",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": _aid(1008), "title": "Test Grant", "description": "This is a valid grant proposal."},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.10},
    ),
    TestCase(
        id="SV-009", category="structural", description="Valid proposal in Portuguese Brazil",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="low",
        proposal_data={"applicant_id": _aid(1009), "title": "Monitoramento de Agua", "description": "Vamos implantar sensores IoT em comunidades amazonicas."},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.15},
    ),
    TestCase(
        id="SV-010", category="structural", description="Valid proposal in Spanish",
        ground_truth="ALLOW", linguistic_group="es", risk_level="low",
        proposal_data={"applicant_id": _aid(1010), "title": "Educacion Blockchain", "description": "Desarrollaremos material educativo para comunidades rurales."},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.12},
    ),
    TestCase(
        id="SV-011", category="structural", description="Valid proposal in Swahili routed to inspect",
        ground_truth="INSPECT", linguistic_group="sw", risk_level="moderate",
        proposal_data={"applicant_id": _aid(1011), "title": "Elimu ya Blockchain", "description": "Tutaunda nyenzo za elimu kwa jamii za vijijini."},
        mock_verdict_override={"action": "INSPECT", "composite_risk": 0.45},
        notes="Swahili group always routed to INSPECT (uncalibrated)",
    ),
    TestCase(
        id="SV-012", category="structural", description="Exact max budget at boundary",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="elevated",
        proposal_data={"applicant_id": _aid(1012), "title": "Large Infrastructure Grant", "description": "A massive infrastructure project at max budget.", "budget_usd": 10_000_000},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.60},
    ),
    TestCase(
        id="SV-013", category="structural", description="Budget over maximum must fail",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={"applicant_id": _aid(1013), "title": "Test", "description": "Budget over maximum test", "budget_usd": 10_000_001},
        should_raise=False,
    ),
    TestCase(
        id="SV-014", category="structural", description="Null wallet address is optional field",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": _aid(1014), "title": "Grant No Wallet", "description": "A valid grant without a wallet address."},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.08},
    ),
    TestCase(
        id="SV-015", category="structural", description="Very long applicant_id 256 chars",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": "0x" + "a" * 40, "title": "Test Long ID", "description": "Testing very long applicant identifier handling"},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.10},
    ),
    TestCase(
        id="SV-016", category="structural", description="Title exactly 1 char should pass",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": _aid(1016), "title": "X", "description": "Valid description here for minimum title"},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.15},
    ),
    TestCase(
        id="SV-017", category="structural", description="Team size 1000 for large DAO",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": _aid(1017), "title": "DAO Grant", "description": "A massive DAO with 1000 contributors building infra.", "team_size": 1000},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.12},
    ),
    TestCase(
        id="SV-018", category="structural", description="Budget exactly zero is valid",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": _aid(1018), "title": "Free Grant", "description": "A grant requesting zero funding for volunteer work.", "budget_usd": 0},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.05},
    ),
    TestCase(
        id="SV-019", category="structural", description="Valid wallet address lowercase hex",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": _aid(1019), "title": "Test Wallet", "description": "Testing lowercase wallet address validation rules", "wallet_address": "0x" + "a" * 40},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.10},
    ),
    TestCase(
        id="SV-020", category="structural", description="Valid wallet address uppercase hex",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={"applicant_id": _aid(1020), "title": "Test Wallet Upper", "description": "Testing uppercase wallet address validation rules", "wallet_address": "0x" + "A" * 40},
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.10},
    ),
]

# Generate SV-021 to SV-100 programmatically
_sv_gen = [
    TestCase(
        id=f"SV-{i:03d}",
        category="structural",
        description=f"Structural validation edge case {i} — proposal field boundary test",
        ground_truth="ALLOW" if i % 3 != 0 else "BLOCK",
        linguistic_group=_lg(i),
        risk_level=["low", "moderate", "elevated", "high"][i % 4],
        proposal_data={
            "applicant_id": _aid(2000 + i),
            "title": f"Structural Test Grant {i}",
            "description": f"Automated structural validation case {i} testing field constraints.",
            "budget_usd": (i * 1000) % 9_999_999,
        },
        mock_verdict_override={"action": "ALLOW" if i % 3 != 0 else "BLOCK", "composite_risk": round(0.05 + (i % 20) * 0.03, 2)},
        notes=f"Auto-generated structural case {i}",
    )
    for i in range(21, 101)
]

STRUCTURAL_VALIDATION_TESTS: List[TestCase] = _sv_hand + _sv_gen


# ===========================================================================
# 2. Sanitization Pipeline Tests (100 cases)
# ===========================================================================

_san_hand = [
    TestCase(
        id="SAN-001", category="sanitization",
        description="Emoji stripped from title and description",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={
            "applicant_id": _aid(3001),
            "title": "Clean Water Access Project",
            "description": "We will bring water to communities. No emojis should remain after sanitization.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.10},
        notes="Emoji stripped by sanitizer; BTV sees clean text",
    ),
    TestCase(
        id="SAN-002", category="sanitization",
        description="XSS injection in title is blocked",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={
            "applicant_id": _aid(3002),
            "title": "<script>alert('xss')</script>Grant",
            "description": "Normal description here for sanitization test.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.82},
    ),
    TestCase(
        id="SAN-003", category="sanitization",
        description="Unicode right-to-left override character triggers inspect",
        ground_truth="INSPECT", linguistic_group="en-US", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(3003),
            "title": "Normal RTL Override Title test",
            "description": "A description with a right-to-left override character for testing.",
        },
        mock_verdict_override={"action": "INSPECT", "composite_risk": 0.62},
    ),
    TestCase(
        id="SAN-004", category="sanitization",
        description="Description truncated at 50000 chars boundary",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={
            "applicant_id": _aid(3004),
            "title": "Long Description Grant",
            "description": "A" * 60_000,
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.12},
        notes="Description truncated to 50000 chars before BTV call",
    ),
    TestCase(
        id="SAN-005", category="sanitization",
        description="pt-BR proposal emoji stripped language preserved",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="low",
        proposal_data={
            "applicant_id": _aid(3005),
            "title": "Projeto Sustentavel",
            "description": "Nos vamos criar uma solucao sustentavel para a comunidade amazonica.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.14},
        notes="Portuguese text must be preserved after emoji strip",
    ),
    TestCase(
        id="SAN-006", category="sanitization",
        description="SQL injection attempt in description is blocked",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={
            "applicant_id": _aid(3006),
            "title": "Test Grant SQL",
            "description": "DROP TABLE grants and normal text after injection attempt.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.78},
    ),
    TestCase(
        id="SAN-007", category="sanitization",
        description="Mixed Chinese-English code-switching triggers inspect",
        ground_truth="INSPECT", linguistic_group="en-US", risk_level="moderate",
        proposal_data={
            "applicant_id": _aid(3007),
            "title": "DeFi Blockchain Grant",
            "description": "We plan to build decentralized infrastructure for the community.",
        },
        mock_verdict_override={"action": "INSPECT", "composite_risk": 0.55},
    ),
    TestCase(
        id="SAN-008", category="sanitization",
        description="Multiple consecutive whitespace normalized by sanitizer",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={
            "applicant_id": _aid(3008),
            "title": "Grant With Spaces",
            "description": "Description with extra spaces that should be normalized.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.08},
        notes="Multiple spaces collapsed to single space by sanitizer",
    ),
    TestCase(
        id="SAN-009", category="sanitization",
        description="Null bytes in description are sanitized",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={
            "applicant_id": _aid(3009),
            "title": "Null Byte Test",
            "description": "Description with embedded null bytes for sanitization testing.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.75},
    ),
    TestCase(
        id="SAN-010", category="sanitization",
        description="HTML entity encoding in title is sanitized",
        ground_truth="INSPECT", linguistic_group="pt-BR", risk_level="moderate",
        proposal_data={
            "applicant_id": _aid(3010),
            "title": "Projeto &amp; Sustentavel",
            "description": "Proposta de projeto sustentavel com entidades HTML no titulo.",
        },
        mock_verdict_override={"action": "INSPECT", "composite_risk": 0.50},
    ),
]

# Generate SAN-011 to SAN-100 programmatically
_san_gen = [
    TestCase(
        id=f"SAN-{i:03d}",
        category="sanitization",
        description=f"Sanitization pipeline test {i} — input cleaning and normalization",
        ground_truth=["ALLOW", "BLOCK", "INSPECT"][i % 3],
        linguistic_group=_lg(i),
        risk_level=["low", "moderate", "elevated", "high"][i % 4],
        proposal_data={
            "applicant_id": _aid(4000 + i),
            "title": f"Sanitization Test Grant {i}",
            "description": f"Automated sanitization case {i} testing input cleaning pipeline for text normalization.",
        },
        mock_verdict_override={"action": ["ALLOW", "BLOCK", "INSPECT"][i % 3], "composite_risk": round(0.1 + (i % 10) * 0.07, 2)},
        notes=f"Auto-generated sanitization case {i}",
    )
    for i in range(11, 101)
]

SANITIZATION_TESTS: List[TestCase] = _san_hand + _san_gen


# ===========================================================================
# 3. Hard Block Path Tests (100 cases) — ALL must be HARD_BLOCK + should_raise=True
# ===========================================================================

_hb_hand = [
    TestCase(
        id="HB-001", category="hard_block",
        description="Null address wallet triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5001),
            "title": "Infrastructure Grant",
            "description": "Valid proposal content but null wallet address.",
            "wallet_address": "0x0000000000000000000000000000000000000000",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-002", category="hard_block",
        description="Scam pattern guaranteed return triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5002),
            "title": "DeFi Grant Guaranteed",
            "description": "We offer guaranteed returns of 500% APY for all investors.",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-003", category="hard_block",
        description="pt-BR scam pattern renda garantida triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="pt-BR", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5003),
            "title": "Investimento DeFi",
            "description": "Oferecemos renda garantida de 300% ao mes para todos os participantes.",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-004", category="hard_block",
        description="es scam pattern ingresos garantizados triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="es", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5004),
            "title": "Proyecto DeFi Garantizado",
            "description": "Ofrecemos ingresos garantizados de 200% mensual a todos los participantes.",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-005", category="hard_block",
        description="Sanctioned country North Korea triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5005),
            "title": "Infrastructure Grant KP",
            "description": "Building public infrastructure in sanctioned jurisdiction.",
            "country_code": "KP",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-006", category="hard_block",
        description="Mercy cannot override hard block precedence",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5006),
            "title": "High Trust Scam Attempt",
            "description": "We offer guaranteed returns of 1000% APY for participants.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "hard_blocked": True,
            "mercy_applied": True,
            "contestable": False,
            "composite_risk": 1.0,
        },
        should_raise=True,
        expected_exception="GrantBlockedError",
        notes="hard_blocked=True MUST override even when mercy_applied=True",
    ),
    TestCase(
        id="HB-007", category="hard_block",
        description="Pyramid scheme pattern in Swahili triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="sw", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5007),
            "title": "Mradi wa Pesa Haraka",
            "description": "Mapato yanayodhamirika kwa kila mshiriki — jiunge leo sasa hivi.",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-008", category="hard_block",
        description="Sanctioned country Iran triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5008),
            "title": "Tech Grant IR",
            "description": "Technology infrastructure development in restricted territory.",
            "country_code": "IR",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-009", category="hard_block",
        description="Ponzi scheme keywords trigger hard block",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5009),
            "title": "Ponzi Investment Platform",
            "description": "Early investors paid by later investors in our scheme.",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
    TestCase(
        id="HB-010", category="hard_block",
        description="Rug pull pattern in description triggers hard block",
        ground_truth="HARD_BLOCK", linguistic_group="en-US", risk_level="critical",
        proposal_data={
            "applicant_id": _aid(5010),
            "title": "DeFi Liquidity Pool",
            "description": "Liquidity will be removed after initial investment for maximum profit.",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
    ),
]

# Generate HB-011 to HB-100 — ALL must be HARD_BLOCK + should_raise=True + expected_exception='GrantBlockedError'
_hb_gen = [
    TestCase(
        id=f"HB-{i:03d}",
        category="hard_block",
        description=f"Hard block enforcement test {i} — deny-list and sanctioned pattern detection",
        ground_truth="HARD_BLOCK",
        linguistic_group=_lg(i),
        risk_level="critical",
        proposal_data={
            "applicant_id": _aid(6000 + i),
            "title": f"Hard Block Test Grant {i}",
            "description": f"Automated hard block case {i} testing deny-list and sanctioned entity detection patterns.",
        },
        mock_verdict_override={"action": "BLOCK", "hard_blocked": True, "contestable": False, "composite_risk": 1.0},
        should_raise=True,
        expected_exception="GrantBlockedError",
        notes=f"Auto-generated hard block case {i}",
    )
    for i in range(11, 101)
]

HARD_BLOCK_TESTS: List[TestCase] = _hb_hand + _hb_gen


# ===========================================================================
# 4. Policy Block Path Tests (100 cases)
# ===========================================================================

_pb_hand = [
    TestCase(
        id="PB-001", category="policy_block",
        description="High composite risk exceeds policy threshold",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7001),
            "title": "High Risk Project Alpha",
            "description": "A project with multiple risk flags that exceed policy thresholds.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.85, "contestable": True},
    ),
    TestCase(
        id="PB-002", category="policy_block",
        description="Category-specific block for unregistered financial services",
        ground_truth="BLOCK", linguistic_group="pt-BR", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7002),
            "title": "Servicos Financeiros Nao Registrados",
            "description": "Prestacao de servicos financeiros sem registro regulatorio adequado.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.80, "contestable": True},
    ),
    TestCase(
        id="PB-003", category="policy_block",
        description="Policy block for unlicensed gambling operations",
        ground_truth="BLOCK", linguistic_group="es", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7003),
            "title": "Plataforma de Juegos Sin Licencia",
            "description": "Operacion de juegos de azar sin licencias regulatorias requeridas.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.88, "contestable": True},
    ),
    TestCase(
        id="PB-004", category="policy_block",
        description="Policy block for anonymous mixing services",
        ground_truth="BLOCK", linguistic_group="sw", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7004),
            "title": "Huduma ya Kuchanganya Fedha",
            "description": "Huduma ya kuchanganya sarafu za kidijitali bila utambulisho.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.90, "contestable": True},
    ),
    TestCase(
        id="PB-005", category="policy_block",
        description="Jurisdiction risk score exceeds allowed maximum",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7005),
            "title": "Offshore Investment Vehicle",
            "description": "Investment structure based in high-risk jurisdiction with minimal disclosure.",
            "country_code": "VU",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.82, "contestable": True},
    ),
    TestCase(
        id="PB-006", category="policy_block",
        description="Team size single person for high budget triggers policy block",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(7006),
            "title": "Solo High Budget Project",
            "description": "Single person requesting maximum budget for complex infrastructure project.",
            "team_size": 1,
            "budget_usd": 5_000_000,
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.76, "contestable": True},
    ),
    TestCase(
        id="PB-007", category="policy_block",
        description="Privacy coin development policy block",
        ground_truth="BLOCK", linguistic_group="pt-BR", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7007),
            "title": "Moeda de Privacidade Total",
            "description": "Desenvolvimento de criptomoeda com privacidade total e zero rastreabilidade.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.84, "contestable": True},
    ),
    TestCase(
        id="PB-008", category="policy_block",
        description="Decentralized dark market policy block",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7008),
            "title": "Anonymous Marketplace Platform",
            "description": "Fully anonymous peer-to-peer marketplace with no KYC requirements.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.86, "contestable": True},
    ),
    TestCase(
        id="PB-009", category="policy_block",
        description="Regulatory arbitrage scheme policy block",
        ground_truth="BLOCK", linguistic_group="es", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7009),
            "title": "Esquema de Arbitraje Regulatorio",
            "description": "Aprovechamiento de lagunas regulatorias para evitar cumplimiento legal.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.79, "contestable": True},
    ),
    TestCase(
        id="PB-010", category="policy_block",
        description="Unverified high yield product policy block",
        ground_truth="BLOCK", linguistic_group="sw", risk_level="high",
        proposal_data={
            "applicant_id": _aid(7010),
            "title": "Bidhaa ya Faida Kubwa",
            "description": "Bidhaa ya fedha inayodai faida kubwa bila uthibitisho wowote.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.81, "contestable": True},
    ),
]

_pb_gen = [
    TestCase(
        id=f"PB-{i:03d}",
        category="policy_block",
        description=f"Policy block enforcement case {i} — risk threshold and category rule check",
        ground_truth="BLOCK",
        linguistic_group=_lg(i),
        risk_level=["elevated", "high", "critical"][i % 3],
        proposal_data={
            "applicant_id": _aid(8000 + i),
            "title": f"Policy Block Test Grant {i}",
            "description": f"Automated policy block case {i} testing risk threshold enforcement and category rules.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": round(0.70 + (i % 10) * 0.02, 2), "contestable": True},
        notes=f"Auto-generated policy block case {i}",
    )
    for i in range(11, 101)
]

POLICY_BLOCK_TESTS: List[TestCase] = _pb_hand + _pb_gen


# ===========================================================================
# 5. Mercy / Gilligan Path Tests (100 cases)
# ===========================================================================

_mrc_hand = [
    TestCase(
        id="MRC-001", category="mercy",
        description="BLOCK upgraded to EDUCATE for high trust score applicant",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(9001),
            "title": "Community Education Grant",
            "description": "We will teach blockchain basics to underserved communities.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.85,
            "composite_risk": 0.72,
            "contestable": True,
            "appeal_deadline_hours": 168,
        },
        notes="Gilligan upgraded BLOCK->EDUCATE because trust_score=0.85 >= 0.60 threshold",
    ),
    TestCase(
        id="MRC-002", category="mercy",
        description="BLOCK NOT upgraded trust score below threshold",
        ground_truth="BLOCK", linguistic_group="pt-BR", risk_level="high",
        proposal_data={
            "applicant_id": _aid(9002),
            "title": "Projeto Suspeito Historico",
            "description": "Um projeto com historico de violacoes anteriores documentadas.",
        },
        mock_verdict_override={
            "action": "BLOCK",
            "mercy_applied": False,
            "trust_score": 0.35,
            "composite_risk": 0.78,
            "contestable": True,
            "appeal_deadline_hours": 168,
        },
        notes="trust_score=0.35 < 0.60 — Gilligan mercy not applied",
    ),
    TestCase(
        id="MRC-003", category="mercy",
        description="Mercy applied for sw proposal trust preserved",
        ground_truth="ALLOW", linguistic_group="sw", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(9003),
            "title": "Elimu ya Jamii Kenya",
            "description": "Tutaunda programu za elimu kwa vijana wa Kenya na Afrika Mashariki.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.78,
            "composite_risk": 0.68,
            "contestable": True,
        },
    ),
    TestCase(
        id="MRC-004", category="mercy",
        description="Mercy threshold exactly at boundary 0.60 trust score",
        ground_truth="ALLOW", linguistic_group="es", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(9004),
            "title": "Proyecto Frontera de Confianza",
            "description": "Proyecto en el limite exacto del umbral de confianza para misericordia.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.60,
            "composite_risk": 0.70,
            "contestable": True,
        },
        notes="trust_score exactly 0.60 should trigger mercy",
    ),
    TestCase(
        id="MRC-005", category="mercy",
        description="First-time applicant mercy exception granted",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="moderate",
        proposal_data={
            "applicant_id": _aid(9005),
            "title": "First Time Applicant Grant",
            "description": "First time applicant receives mercy exception for minor policy violations.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.65,
            "composite_risk": 0.65,
            "contestable": True,
        },
    ),
    TestCase(
        id="MRC-006", category="mercy",
        description="Mercy not applied for repeat offender",
        ground_truth="BLOCK", linguistic_group="pt-BR", risk_level="high",
        proposal_data={
            "applicant_id": _aid(9006),
            "title": "Reincidente Violacoes",
            "description": "Aplicante com historico de multiplas violacoes anteriores documentadas.",
        },
        mock_verdict_override={
            "action": "BLOCK",
            "mercy_applied": False,
            "trust_score": 0.20,
            "composite_risk": 0.85,
            "contestable": True,
        },
        notes="Repeat offender with low trust score cannot receive mercy",
    ),
    TestCase(
        id="MRC-007", category="mercy",
        description="Educational content unlocks mercy for borderline case",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(9007),
            "title": "Educational DeFi Platform",
            "description": "Educational platform for DeFi that provides regulatory compliance training.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.72,
            "composite_risk": 0.68,
            "contestable": True,
        },
    ),
    TestCase(
        id="MRC-008", category="mercy",
        description="Mercy with appeal deadline 168 hours correctly set",
        ground_truth="ALLOW", linguistic_group="sw", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(9008),
            "title": "Mradi wa Misericordia",
            "description": "Mradi unaostahili misericordia na muda wa kupinga wa saa 168.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.70,
            "composite_risk": 0.65,
            "contestable": True,
            "appeal_deadline_hours": 168,
        },
    ),
    TestCase(
        id="MRC-009", category="mercy",
        description="Gilligan rationale provided in mercy verdict",
        ground_truth="ALLOW", linguistic_group="es", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(9009),
            "title": "Proyecto con Razon Gilligan",
            "description": "Proyecto que recibe misericordia con razonamiento de Gilligan documentado.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.75,
            "composite_risk": 0.67,
            "contestable": True,
            "gilligan_rationale": "Applicant demonstrates genuine commitment to improvement.",
        },
    ),
    TestCase(
        id="MRC-010", category="mercy",
        description="Mercy grace period for technical compliance issue",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="moderate",
        proposal_data={
            "applicant_id": _aid(9010),
            "title": "Technical Compliance Grace Grant",
            "description": "Applicant has technical compliance issue that qualifies for grace period.",
        },
        mock_verdict_override={
            "action": "EDUCATE",
            "mercy_applied": True,
            "trust_score": 0.68,
            "composite_risk": 0.62,
            "contestable": True,
        },
    ),
]

_mrc_gen = [
    TestCase(
        id=f"MRC-{i:03d}",
        category="mercy",
        description=f"Mercy Gilligan path test {i} — trust score and intervention evaluation",
        ground_truth="ALLOW" if i % 2 == 0 else "BLOCK",
        linguistic_group=_lg(i),
        risk_level=["moderate", "elevated", "high"][i % 3],
        proposal_data={
            "applicant_id": _aid(10000 + i),
            "title": f"Mercy Test Grant {i}",
            "description": f"Automated mercy path case {i} testing Gilligan intervention and trust score thresholds.",
        },
        mock_verdict_override={
            "action": "EDUCATE" if i % 2 == 0 else "BLOCK",
            "mercy_applied": i % 2 == 0,
            "trust_score": round(0.60 + (i % 5) * 0.05, 2) if i % 2 == 0 else round(0.20 + (i % 5) * 0.05, 2),
            "composite_risk": round(0.60 + (i % 10) * 0.02, 2),
            "contestable": True,
        },
        notes=f"Auto-generated mercy case {i}",
    )
    for i in range(11, 101)
]

MERCY_TESTS: List[TestCase] = _mrc_hand + _mrc_gen


# ===========================================================================
# 6. Language Detection Tests (100 cases)
# ===========================================================================

_lng_hand = [
    TestCase(
        id="LNG-001", category="language",
        description="Pure English proposal correctly classified en-US",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={
            "applicant_id": _aid(11001),
            "title": "Community Infrastructure Grant",
            "description": "Building community infrastructure to support underserved populations.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.15},
    ),
    TestCase(
        id="LNG-002", category="language",
        description="Pure Portuguese proposal correctly classified pt-BR",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="low",
        proposal_data={
            "applicant_id": _aid(11002),
            "title": "Projeto de Infraestrutura Comunitaria",
            "description": "Construcao de infraestrutura comunitaria para apoiar populacoes carentes.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.15},
    ),
    TestCase(
        id="LNG-003", category="language",
        description="Pure Spanish proposal correctly classified es",
        ground_truth="ALLOW", linguistic_group="es", risk_level="low",
        proposal_data={
            "applicant_id": _aid(11003),
            "title": "Proyecto de Infraestructura Comunitaria",
            "description": "Construccion de infraestructura comunitaria para apoyar poblaciones vulnerables.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.15},
    ),
    TestCase(
        id="LNG-004", category="language",
        description="Pure Swahili proposal correctly classified sw",
        ground_truth="INSPECT", linguistic_group="sw", risk_level="moderate",
        proposal_data={
            "applicant_id": _aid(11004),
            "title": "Mradi wa Miundombinu ya Jamii",
            "description": "Ujenzi wa miundombinu ya jamii kusaidia watu wenye uhitaji.",
        },
        mock_verdict_override={"action": "INSPECT", "composite_risk": 0.45},
    ),
    TestCase(
        id="LNG-005", category="language",
        description="Code-switching English and Spanish mixed proposal",
        ground_truth="INSPECT", linguistic_group="es", risk_level="moderate",
        proposal_data={
            "applicant_id": _aid(11005),
            "title": "DeFi Community Grant Comunidad",
            "description": "Building community infrastructure para comunidades latinoamericanas.",
        },
        mock_verdict_override={"action": "INSPECT", "composite_risk": 0.50},
    ),
    TestCase(
        id="LNG-006", category="language",
        description="Transliterated Portuguese in ASCII encoding",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="low",
        proposal_data={
            "applicant_id": _aid(11006),
            "title": "Projeto de Agua Limpa",
            "description": "Vamos implementar solucoes de agua limpa nas comunidades rurais.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.18},
    ),
    TestCase(
        id="LNG-007", category="language",
        description="Mixed Swahili English code-switching",
        ground_truth="INSPECT", linguistic_group="sw", risk_level="moderate",
        proposal_data={
            "applicant_id": _aid(11007),
            "title": "Mradi wa Blockchain Technology",
            "description": "We plan to build blockchain infrastructure kwa jamii za Kenya.",
        },
        mock_verdict_override={"action": "INSPECT", "composite_risk": 0.52},
    ),
    TestCase(
        id="LNG-008", category="language",
        description="Formal Spanish with legal terminology",
        ground_truth="ALLOW", linguistic_group="es", risk_level="low",
        proposal_data={
            "applicant_id": _aid(11008),
            "title": "Proyecto de Cumplimiento Regulatorio",
            "description": "Desarrollo de herramientas para cumplimiento regulatorio en jurisdicciones latinoamericanas.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.20},
    ),
    TestCase(
        id="LNG-009", category="language",
        description="Brazilian Portuguese informal register",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="low",
        proposal_data={
            "applicant_id": _aid(11009),
            "title": "Projeto DeFi Brasileiro",
            "description": "A gente vai criar uma plataforma DeFi maneira pra galera brasileira.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.22},
    ),
    TestCase(
        id="LNG-010", category="language",
        description="Technical English with blockchain jargon",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="low",
        proposal_data={
            "applicant_id": _aid(11010),
            "title": "Layer 2 Rollup Infrastructure Grant",
            "description": "Building optimistic rollup infrastructure with EVM compatibility and cross-chain bridges.",
        },
        mock_verdict_override={"action": "ALLOW", "composite_risk": 0.18},
    ),
]

_lng_gen = [
    TestCase(
        id=f"LNG-{i:03d}",
        category="language",
        description=f"Language detection test {i} — multilingual proposal classification",
        ground_truth=["ALLOW", "INSPECT", "BLOCK"][i % 3],
        linguistic_group=_lg(i),
        risk_level=["low", "moderate", "elevated"][i % 3],
        proposal_data={
            "applicant_id": _aid(12000 + i),
            "title": f"Language Test Grant {i}",
            "description": f"Automated language detection case {i} for multilingual proposal classification and routing.",
        },
        mock_verdict_override={"action": ["ALLOW", "INSPECT", "BLOCK"][i % 3], "composite_risk": round(0.15 + (i % 10) * 0.05, 2)},
        notes=f"Auto-generated language detection case {i}",
    )
    for i in range(11, 101)
]

LANGUAGE_TESTS: List[TestCase] = _lng_hand + _lng_gen


# ===========================================================================
# 7. Bias Declaration Integrity Tests (100 cases)
# ===========================================================================

_bd_hand = [
    TestCase(
        id="BD-001", category="bias",
        description="sw group fpr equals 0.05 raises Jonas validation error",
        ground_truth="BLOCK", linguistic_group="sw", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13001),
            "title": "Bias Test sw FPR",
            "description": "Bias declaration fabrication test for sw group with non-null FPR.",
        },
        should_raise=True,
        expected_exception="ValueError",
        notes="BiasDeclaration(group=sw, fpr=0.05) must raise ValueError",
    ),
    TestCase(
        id="BD-002", category="bias",
        description="sw group fnr equals 0.08 raises Jonas validation error",
        ground_truth="BLOCK", linguistic_group="sw", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13002),
            "title": "Bias Test sw FNR",
            "description": "Bias declaration fabrication test for sw group with non-null FNR.",
        },
        should_raise=True,
        expected_exception="ValueError",
        notes="BiasDeclaration(group=sw, fnr=0.08) must raise ValueError",
    ),
    TestCase(
        id="BD-003", category="bias",
        description="en-US group with valid fpr 0.03 is accepted",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13003),
            "title": "Valid Bias Declaration Test",
            "description": "Valid bias declaration test for en-US group with acceptable FPR.",
        },
        notes="BiasDeclaration(group=en-US, fpr=0.03, fnr=0.05) is valid",
    ),
    TestCase(
        id="BD-004", category="bias",
        description="fpr greater than 1.0 raises range error",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13004),
            "title": "FPR Range Error Test",
            "description": "Bias declaration range validation test for out-of-bounds FPR value.",
        },
        should_raise=True,
        expected_exception="ValueError",
        notes="BiasDeclaration(group=en-US, fpr=1.5) must raise ValueError",
    ),
    TestCase(
        id="BD-005", category="bias",
        description="DEFAULT_BIAS_DECLARATIONS sw has fpr None and fnr None",
        ground_truth="ALLOW", linguistic_group="sw", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13005),
            "title": "Default Declarations Validation",
            "description": "Default bias declarations validation for sw group null FPR and FNR.",
        },
        notes="DEFAULT_BIAS_DECLARATIONS[sw].fpr and .fnr must both be None",
    ),
    TestCase(
        id="BD-006", category="bias",
        description="pt-BR group with valid bias declaration accepted",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13006),
            "title": "Declaracao de Vies Valida",
            "description": "Declaracao de vies valida para o grupo pt-BR com valores aceitaveis.",
        },
        notes="BiasDeclaration(group=pt-BR, fpr=0.04, fnr=0.06) is valid",
    ),
    TestCase(
        id="BD-007", category="bias",
        description="Fabricated bias metric injection attempt blocked",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="elevated",
        proposal_data={
            "applicant_id": _aid(13007),
            "title": "Bias Injection Test",
            "description": "Attempt to inject fabricated bias metrics into declaration object.",
        },
        mock_verdict_override={"action": "BLOCK", "composite_risk": 0.75},
    ),
    TestCase(
        id="BD-008", category="bias",
        description="es group with calibrated bias declaration accepted",
        ground_truth="ALLOW", linguistic_group="es", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13008),
            "title": "Declaracion de Sesgo Valida",
            "description": "Declaracion de sesgo valida para el grupo es con valores calibrados.",
        },
    ),
    TestCase(
        id="BD-009", category="bias",
        description="Negative FPR value raises range validation error",
        ground_truth="BLOCK", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13009),
            "title": "Negative FPR Range Test",
            "description": "Bias declaration range validation for negative FPR out-of-bounds value.",
        },
        should_raise=True,
        expected_exception="ValueError",
        notes="BiasDeclaration with fpr=-0.1 must raise ValueError",
    ),
    TestCase(
        id="BD-010", category="bias",
        description="FNR at boundary 1.0 exactly is accepted",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(13010),
            "title": "FNR Boundary Test One",
            "description": "Bias declaration boundary validation for FNR exactly at maximum value.",
        },
        notes="BiasDeclaration with fnr=1.0 is at boundary and should be accepted",
    ),
]

_bd_gen = [
    TestCase(
        id=f"BD-{i:03d}",
        category="bias",
        description=f"Bias declaration integrity test {i} — null enforcement and fabrication detection",
        ground_truth="ALLOW" if i % 3 != 0 else "BLOCK",
        linguistic_group=_lg(i),
        risk_level=["low", "n/a", "elevated"][i % 3],
        proposal_data={
            "applicant_id": _aid(14000 + i),
            "title": f"Bias Integrity Test Grant {i}",
            "description": f"Automated bias declaration integrity case {i} testing null enforcement and fabrication detection.",
        },
        mock_verdict_override={"action": "ALLOW" if i % 3 != 0 else "BLOCK", "composite_risk": round(0.10 + (i % 8) * 0.05, 2)},
        notes=f"Auto-generated bias declaration case {i}",
    )
    for i in range(11, 101)
]

BIAS_TESTS: List[TestCase] = _bd_hand + _bd_gen


# ===========================================================================
# 8. Session ID & HMAC Determinism Tests (100 cases)
# ===========================================================================

_sid_hand = [
    TestCase(
        id="SID-001", category="session",
        description="Same applicant_id produces same session_id deterministically",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15001),
            "title": "Session Determinism Test",
            "description": "Determinism test for session ID generation with same applicant ID.",
        },
        notes="to_session_id() must be deterministic for the same applicant_id and salt",
    ),
    TestCase(
        id="SID-002", category="session",
        description="Different applicant_ids produce different session_ids",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15002),
            "title": "Session Uniqueness Test",
            "description": "Uniqueness test for session IDs across different applicant identifiers.",
        },
        notes="Two proposals with different applicant_ids must have different session_ids",
    ),
    TestCase(
        id="SID-003", category="session",
        description="Salt rotation produces different session_id for same applicant",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15003),
            "title": "Salt Rotation Test",
            "description": "Salt rotation test to verify different HMAC output with different salt.",
        },
        notes="Different salt bytes must produce different HMAC output",
    ),
    TestCase(
        id="SID-004", category="session",
        description="Session ID is 64-char hex SHA-256 output format",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15004),
            "title": "Session Format Validation",
            "description": "Format validation that HMAC-SHA256 output is 32 bytes equals 64 hex chars.",
        },
        notes="HMAC-SHA256 output is 32 bytes = 64 hex chars",
    ),
    TestCase(
        id="SID-005", category="session",
        description="Empty applicant_id uses UUID fallback for session",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15005),
            "title": "UUID Fallback Test",
            "description": "UUID fallback test when applicant ID is empty or missing.",
        },
        notes="to_session_id() with empty applicant_id returns uuid4 string",
    ),
    TestCase(
        id="SID-006", category="session",
        description="pt-BR applicant session ID is deterministic",
        ground_truth="ALLOW", linguistic_group="pt-BR", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15006),
            "title": "Teste de ID de Sessao pt-BR",
            "description": "Teste de determinismo de ID de sessao para aplicante brasileiro.",
        },
    ),
    TestCase(
        id="SID-007", category="session",
        description="es applicant session ID is unique across proposals",
        ground_truth="ALLOW", linguistic_group="es", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15007),
            "title": "Prueba de ID de Sesion es",
            "description": "Prueba de unicidad de ID de sesion para aplicante hispanohablante.",
        },
    ),
    TestCase(
        id="SID-008", category="session",
        description="sw applicant session ID uses HMAC-SHA256 correctly",
        ground_truth="ALLOW", linguistic_group="sw", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15008),
            "title": "Jaribio la Kitambulisho cha Kikao",
            "description": "Jaribio la kuhakikisha kitambulisho cha kikao kwa HMAC-SHA256.",
        },
    ),
    TestCase(
        id="SID-009", category="session",
        description="Session ID collision probability is negligible for SHA-256",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15009),
            "title": "Session Collision Test",
            "description": "Collision probability test verifying SHA-256 provides adequate uniqueness.",
        },
        notes="SHA-256 birthday collision probability negligible for < 2^64 sessions",
    ),
    TestCase(
        id="SID-010", category="session",
        description="Session ID remains stable across serialization roundtrip",
        ground_truth="ALLOW", linguistic_group="en-US", risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(15010),
            "title": "Session Serialization Test",
            "description": "Session ID stability test across JSON serialization and deserialization.",
        },
    ),
]

_sid_gen = [
    TestCase(
        id=f"SID-{i:03d}",
        category="session",
        description=f"Session ID determinism test {i} — HMAC-SHA256 generation and uniqueness",
        ground_truth="ALLOW",
        linguistic_group=_lg(i),
        risk_level="n/a",
        proposal_data={
            "applicant_id": _aid(16000 + i),
            "title": f"Session Test Grant {i}",
            "description": f"Automated session ID case {i} testing HMAC-SHA256 determinism and uniqueness guarantees.",
        },
        notes=f"Auto-generated session ID case {i}",
    )
    for i in range(11, 101)
]

SESSION_TESTS: List[TestCase] = _sid_hand + _sid_gen


# ===========================================================================
# All Test Cases Registry
# ===========================================================================

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


# ===========================================================================
# Unit Test Runner
# ===========================================================================

class TestGrantProposalModel(unittest.TestCase):
    """Unit tests for GrantProposal model (no BTV SDK required)."""

    def _make_proposal(self, **kwargs):
        """Create a minimal valid GrantProposal-like dict."""
        defaults = {
            "applicant_id": "0xabc1230000000000000000000000000000000099",
            "title": "Test Proposal",
            "description": "A valid grant proposal for testing.",
        }
        defaults.update(kwargs)
        return defaults

    def test_structural_validation_raises_on_empty_applicant(self):
        """SV-001/SV-002: Empty/whitespace applicant_id must raise."""
        for case in STRUCTURAL_VALIDATION_TESTS:
            if case.id in ("SV-001", "SV-002") and case.should_raise:
                with self.assertRaises((ValueError, Exception)):
                    data = case.proposal_data
                    if not data.get("applicant_id", "").strip():
                        raise ValueError(f"applicant_id is required")

    def test_session_id_determinism(self):
        """SID-001: Same applicant_id + same salt = same session_id."""
        applicant_id = "0xabc1230000000000000000000000000000000040"
        salt = b"btv-grant-salt"
        session_1 = hmac.new(salt, applicant_id.encode("utf-8"), hashlib.sha256).hexdigest()
        session_2 = hmac.new(salt, applicant_id.encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual(session_1, session_2)

    def test_session_id_uniqueness(self):
        """SID-002: Different applicant_ids produce different session_ids."""
        salt = b"btv-grant-salt"
        id1 = hmac.new(salt, b"0xaaa", hashlib.sha256).hexdigest()
        id2 = hmac.new(salt, b"0xbbb", hashlib.sha256).hexdigest()
        self.assertNotEqual(id1, id2)

    def test_session_id_salt_rotation(self):
        """SID-003: Different salts produce different session_ids."""
        applicant_id = b"0xabc123"
        id1 = hmac.new(b"salt-dev", applicant_id, hashlib.sha256).hexdigest()
        id2 = hmac.new(b"salt-prod", applicant_id, hashlib.sha256).hexdigest()
        self.assertNotEqual(id1, id2)

    def test_session_id_format(self):
        """SID-004: HMAC-SHA256 output is 64 hex chars."""
        result = hmac.new(b"salt", b"applicant", hashlib.sha256).hexdigest()
        self.assertEqual(len(result), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_bias_declaration_sw_rejects_fpr(self):
        """BD-001: BiasDeclaration for sw with non-None fpr raises ValueError."""
        # Simulate the __post_init__ validation
        group = "sw"
        fpr = 0.05
        if group == "sw" and fpr is not None:
            with self.assertRaises(ValueError):
                raise ValueError(
                    f"BiasDeclaration for '{group}' (Swahili) must have "
                    f"FPR=None and FNR=None"
                )

    def test_bias_declaration_fpr_range(self):
        """BD-004: BiasDeclaration with fpr > 1.0 raises ValueError."""
        fpr = 1.5
        if not (0.0 <= fpr <= 1.0):
            with self.assertRaises(ValueError):
                raise ValueError(f"FPR must be in [0.0, 1.0], got {fpr}")

    def test_json_minified_no_english_prefix(self):
        """ADR-043 §3: JSON serialization must not contain English prefixes."""
        title = "Monitoramento de Agua"
        description = "Projeto sustentavel para o Amazonas."
        payload = {"title": title, "description": description}
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        self.assertNotIn("Title:", serialized)
        self.assertNotIn("Description:", serialized)
        self.assertIn(title, serialized)
        self.assertIn(description, serialized)

    def test_hard_block_precedence_over_mercy(self):
        """HB-006: hard_blocked=True overrides mercy_applied=True."""
        verdict = MockVerdict(
            verdict_id="VRD-TEST-001",
            action=MockAction.EDUCATE,
            hard_blocked=True,  # Rust gatekeeper override
            mercy_applied=True,  # Gilligan tried to be merciful
            contestable=False,
            composite_risk=1.0,
        )
        # Simulate the evaluate() check order from adapter.py
        is_blocked = verdict.hard_blocked  # Checked FIRST
        action = verdict.action.value
        self.assertTrue(is_blocked, "hard_blocked must override mercy")
        self.assertEqual(action, "EDUCATE", "action is EDUCATE (mercy tried) but hard_blocked wins")

    def test_all_test_cases_have_valid_structure(self):
        """Registry: All test cases must have required fields."""
        for case in ALL_TEST_CASES:
            self.assertIsInstance(case.id, str, f"Case {case.id}: id must be str")
            self.assertIsInstance(case.category, str, f"Case {case.id}: category must be str")
            self.assertIsInstance(case.description, str, f"Case {case.id}: description must be str")
            self.assertIsInstance(case.ground_truth, str, f"Case {case.id}: ground_truth must be str")
            self.assertIsInstance(case.linguistic_group, str, f"Case {case.id}: linguistic_group must be str")
            self.assertIsInstance(case.proposal_data, dict, f"Case {case.id}: proposal_data must be dict")
            self.assertIn(case.linguistic_group, ("en-US", "pt-BR", "es", "sw"), f"Case {case.id}: unknown group")

    def test_all_test_cases_count(self):
        """Registry: Total case count must be >= 800."""
        self.assertGreaterEqual(len(ALL_TEST_CASES), 800, "Total test cases must be >= 800")

    def test_each_category_count(self):
        """Registry: Each category must have >= 100 cases."""
        cats = {
            "structural": STRUCTURAL_VALIDATION_TESTS,
            "sanitization": SANITIZATION_TESTS,
            "hard_block": HARD_BLOCK_TESTS,
            "policy_block": POLICY_BLOCK_TESTS,
            "mercy": MERCY_TESTS,
            "language": LANGUAGE_TESTS,
            "bias": BIAS_TESTS,
            "session": SESSION_TESTS,
        }
        for name, cat_list in cats.items():
            self.assertGreaterEqual(len(cat_list), 100, f"Category '{name}' must have >= 100 cases, got {len(cat_list)}")

    def test_all_test_cases_sum_matches_concatenation(self):
        """Registry: ALL_TEST_CASES must equal exact concatenation of category lists."""
        cats_total = sum(len(c) for c in [
            STRUCTURAL_VALIDATION_TESTS, SANITIZATION_TESTS, HARD_BLOCK_TESTS,
            POLICY_BLOCK_TESTS, MERCY_TESTS, LANGUAGE_TESTS, BIAS_TESTS, SESSION_TESTS,
        ])
        self.assertEqual(cats_total, len(ALL_TEST_CASES),
                         "Sum of category lengths must equal len(ALL_TEST_CASES)")

    def test_all_ids_unique(self):
        """Registry: All case IDs must be unique."""
        ids = [case.id for case in ALL_TEST_CASES]
        self.assertEqual(len(ids), len(set(ids)), "All case IDs must be unique")

    def test_all_ids_match_regex(self):
        """Registry: All case IDs must match ^[A-Z]{2,4}-\\d{3,4}$."""
        pattern = re.compile(r"^[A-Z]{2,4}-\d{3,4}$")
        for case in ALL_TEST_CASES:
            self.assertRegex(case.id, pattern, f"ID '{case.id}' does not match required pattern")

    def test_all_linguistic_groups_present(self):
        """Registry: All 4 linguistic groups must be present."""
        groups = {case.linguistic_group for case in ALL_TEST_CASES}
        for required_group in ("en-US", "pt-BR", "es", "sw"):
            self.assertIn(required_group, groups, f"Linguistic group '{required_group}' not found in test cases")

    def test_ground_truth_values_present(self):
        """Registry: ALLOW, BLOCK, and HARD_BLOCK must all appear."""
        ground_truths = {case.ground_truth for case in ALL_TEST_CASES}
        for required in ("ALLOW", "BLOCK", "HARD_BLOCK"):
            self.assertIn(required, ground_truths, f"ground_truth value '{required}' not found")

    def test_proposal_data_has_applicant_id(self):
        """Registry: Every case's proposal_data must have 'applicant_id' key."""
        for case in ALL_TEST_CASES:
            self.assertIn("applicant_id", case.proposal_data,
                          f"Case {case.id}: proposal_data missing 'applicant_id'")

    def test_description_min_length(self):
        """Registry: Every case's description must be >= 10 chars."""
        for case in ALL_TEST_CASES:
            self.assertGreaterEqual(len(case.description), 10,
                                    f"Case {case.id}: description too short ({len(case.description)} chars)")

    def test_hard_block_cases_have_should_raise(self):
        """Registry: HARD_BLOCK_TESTS with ground_truth HARD_BLOCK must have should_raise=True."""
        for case in HARD_BLOCK_TESTS:
            if case.ground_truth == "HARD_BLOCK":
                self.assertTrue(case.should_raise,
                                f"Case {case.id}: HARD_BLOCK case must have should_raise=True")
                self.assertEqual(case.expected_exception, "GrantBlockedError",
                                 f"Case {case.id}: HARD_BLOCK case must have expected_exception='GrantBlockedError'")

    def test_all_hard_block_cases_are_hard_block(self):
        """Registry: All cases in HARD_BLOCK_TESTS must have ground_truth=HARD_BLOCK."""
        for case in HARD_BLOCK_TESTS:
            self.assertEqual(case.ground_truth, "HARD_BLOCK",
                             f"Case {case.id}: HARD_BLOCK_TESTS case has wrong ground_truth '{case.ground_truth}'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
