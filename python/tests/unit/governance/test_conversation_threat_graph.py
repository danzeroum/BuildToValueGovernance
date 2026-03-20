"""Tests for ConversationThreatGraph — Gap E."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.conversation_threat_graph import (
    ConversationThreatGraph,
    ThreatLevel,
)


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    policy = {
        "window_size": 5,
        "burst_threshold": 3,
        "escalation_threshold_pct": 50,
        "risk_levels": {"low": 0.3, "medium": 0.6, "high": 0.8},
        "attack_sequences": [
            {
                "name": "retry_after_block",
                "pattern": ["BLOCK", "BLOCK", "BLOCK"],
                "severity": "high",
            }
        ],
    }
    p = tmp_path / "threat_patterns.yaml"
    p.write_text(yaml.dump(policy))
    return p


@pytest.fixture
def graph(policy_path: Path) -> ConversationThreatGraph:
    return ConversationThreatGraph(policy_path=policy_path)


class TestRecordTurn:
    def test_single_turn_low(self, graph: ConversationThreatGraph) -> None:
        r = graph.record_turn("s1", "ALLOW", 0.1)
        assert r.threat_level == ThreatLevel.LOW
        assert r.session_id == "s1"

    def test_escalating_turns(self, graph: ConversationThreatGraph) -> None:
        graph.record_turn("s1", "ALLOW", 0.1)
        graph.record_turn("s1", "EDUCATE", 0.3)
        graph.record_turn("s1", "BLOCK", 0.5)
        r = graph.record_turn("s1", "BLOCK", 0.9)
        assert r.escalation_pct > 0
        assert r.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)


class TestBurstDetection:
    def test_burst_triggers_critical(self, graph: ConversationThreatGraph) -> None:
        graph.record_turn("s1", "BLOCK", 0.9)
        graph.record_turn("s1", "BLOCK", 0.85)
        r = graph.record_turn("s1", "BLOCK", 0.9)
        assert r.burst_detected is True
        assert r.threat_level == ThreatLevel.CRITICAL


class TestSequenceMatching:
    def test_known_sequence_detected(self, graph: ConversationThreatGraph) -> None:
        graph.record_turn("s1", "BLOCK", 0.5)
        graph.record_turn("s1", "BLOCK", 0.5)
        r = graph.record_turn("s1", "BLOCK", 0.5)
        assert r.pattern_match == "retry_after_block"
        assert r.threat_level == ThreatLevel.CRITICAL

    def test_no_sequence_match(self, graph: ConversationThreatGraph) -> None:
        graph.record_turn("s1", "ALLOW", 0.1)
        r = graph.record_turn("s1", "EDUCATE", 0.3)
        assert r.pattern_match is None


class TestSessionIsolation:
    def test_separate_sessions(self, graph: ConversationThreatGraph) -> None:
        graph.record_turn("s1", "BLOCK", 0.9)
        graph.record_turn("s1", "BLOCK", 0.9)
        graph.record_turn("s1", "BLOCK", 0.9)
        r_s2 = graph.record_turn("s2", "ALLOW", 0.1)
        assert r_s2.threat_level == ThreatLevel.LOW


class TestHmac:
    def test_hmac_present(self, graph: ConversationThreatGraph) -> None:
        r = graph.record_turn("s1", "ALLOW", 0.1)
        assert len(r.hmac_sha256) == 64


class TestInstructionDensity:
    def test_high_density_triggers_high(self, graph: ConversationThreatGraph) -> None:
        # All instruction-like actions -> density > 0.5 -> HIGH
        graph.record_turn("s1", "system_override", 0.3)
        graph.record_turn("s1", "execute_command", 0.3)
        r = graph.record_turn("s1", "ignore_rules", 0.3)
        assert r.instruction_density > 0.5
        assert r.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

    def test_low_density_stays_low(self, graph: ConversationThreatGraph) -> None:
        r = graph.record_turn("s1", "read_data", 0.1)
        assert r.instruction_density == 0.0
        assert r.threat_level == ThreatLevel.LOW


class TestNoPolicy:
    def test_default_graph(self) -> None:
        g = ConversationThreatGraph()
        r = g.record_turn("s1", "ALLOW", 0.1)
        assert r.threat_level == ThreatLevel.LOW
