"""Tests for CapabilityRegistry — Gap C."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.capability_registry import (
    CapabilityRegistry,
    CapabilityResult,
)


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    policy = {
        "schema_version": "1.0",
        "default_capabilities": ["llm_inference", "read_public_data"],
        "agents": {
            "med-agent": {
                "capabilities": ["llm_inference", "patient_lookup", "lab_read"],
                "revoked": ["lab_read"],
            },
            "full-agent": {
                "capabilities": ["llm_inference", "model_deploy", "model_training"],
                "revoked": [],
            },
        },
        "hierarchy": {
            "model_deploy": {"requires": ["model_training"]},
        },
    }
    p = tmp_path / "capabilities.yaml"
    p.write_text(yaml.dump(policy))
    return p


@pytest.fixture
def registry(policy_path: Path) -> CapabilityRegistry:
    return CapabilityRegistry(policy_path=policy_path)


class TestCapabilityLookup:
    def test_known_agent_has_capability(self, registry: CapabilityRegistry) -> None:
        assert registry.has_capability("med-agent", "llm_inference")
        assert registry.has_capability("med-agent", "patient_lookup")

    def test_revoked_capability_removed(self, registry: CapabilityRegistry) -> None:
        assert not registry.has_capability("med-agent", "lab_read")

    def test_unknown_agent_gets_defaults(self, registry: CapabilityRegistry) -> None:
        caps = registry.capabilities_for("unknown-agent")
        assert "llm_inference" in caps
        assert "read_public_data" in caps
        assert "patient_lookup" not in caps


class TestCheckCapabilities:
    def test_all_present(self, registry: CapabilityRegistry) -> None:
        r = registry.check_capabilities("med-agent", ["llm_inference"])
        assert r.allowed is True
        assert len(r.missing) == 0

    def test_missing_capability(self, registry: CapabilityRegistry) -> None:
        r = registry.check_capabilities("med-agent", ["model_deploy"])
        assert r.allowed is False
        assert "model_deploy" in r.missing

    def test_empty_required(self, registry: CapabilityRegistry) -> None:
        r = registry.check_capabilities("med-agent", [])
        assert r.allowed is True


class TestHierarchy:
    def test_hierarchy_satisfied(self, registry: CapabilityRegistry) -> None:
        r = registry.check_hierarchy("full-agent", "model_deploy")
        assert r.allowed is True

    def test_hierarchy_missing_prereq(self, registry: CapabilityRegistry) -> None:
        r = registry.check_hierarchy("med-agent", "model_deploy")
        assert r.allowed is False


class TestNoPolicy:
    def test_empty_registry(self) -> None:
        reg = CapabilityRegistry()
        caps = reg.capabilities_for("any")
        assert len(caps) == 0
