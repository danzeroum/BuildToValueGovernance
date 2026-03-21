"""
PolicyEngine unit tests — ADR-011 / v1.6.0
12 casos: ALLOW, BLOCK, ESCALATE, REDACT, fail-secure, HMAC, explain,
          operadores (contains, in, gt, lte), rule_count, sla_deadline.
"""
import pytest
from pathlib import Path
import yaml
from buildtovalue.governance.policy_engine import (
    PolicyEngine, PolicyAction, PolicyRule, PolicySeverity, PolicyEvalResult,
    ArtifactAllowlistConfig,
)


def _make_rule(
    rule_id: str,
    action: PolicyAction,
    field: str = "composite_risk",
    op: str = "gt",
    value: object = 0.9,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        description=f"Regra de teste {rule_id}",
        action=action,
        severity=PolicySeverity.HIGH,
        condition_field=field,
        condition_operator=op,
        condition_value=value,
        adr_refs=["ADR-011"],
    )


@pytest.fixture
def empty_engine() -> PolicyEngine:
    return PolicyEngine(policies_dir=Path("/nonexistent_btv_test"))


@pytest.fixture
def engine(empty_engine: PolicyEngine) -> PolicyEngine:
    empty_engine._rules = [
        _make_rule("T-BLOCK",    PolicyAction.BLOCK,    op="gt",  value=0.9),
        _make_rule("T-ESCALATE", PolicyAction.ESCALATE, op="gt",  value=0.7),
        _make_rule("T-REDACT",   PolicyAction.REDACT,   field="pii_detected", op="eq", value="true"),
    ]
    return empty_engine


class TestAllow:
    def test_allow_low_risk(self, engine: PolicyEngine) -> None:
        r = engine.evaluate(0.3, {})
        assert r.action == PolicyAction.ALLOW

    def test_allow_when_no_rules(self, empty_engine: PolicyEngine) -> None:
        r = empty_engine.evaluate(0.99, {})
        assert r.action == PolicyAction.ALLOW


class TestBlock:
    def test_block_critical_risk(self, engine: PolicyEngine) -> None:
        r = engine.evaluate(0.95, {})
        assert r.action == PolicyAction.BLOCK
        assert "T-BLOCK" in r.triggered_rules

    def test_block_worst_case_wins(self, engine: PolicyEngine) -> None:
        # composite_risk=0.85 aciona ESCALATE (>0.7) mas nao BLOCK (>0.9)
        r = engine.evaluate(0.85, {})
        assert r.action == PolicyAction.ESCALATE


class TestEscalate:
    def test_escalate_high_risk(self, engine: PolicyEngine) -> None:
        r = engine.evaluate(0.75, {})
        assert r.action == PolicyAction.ESCALATE
        assert "T-ESCALATE" in r.triggered_rules


class TestRedact:
    def test_redact_pii_context(self, engine: PolicyEngine) -> None:
        r = engine.evaluate(0.1, {"pii_detected": "true"})
        assert r.action == PolicyAction.REDACT
        assert "T-REDACT" in r.triggered_rules


class TestOperators:
    def test_contains_operator(self, empty_engine: PolicyEngine) -> None:
        empty_engine._rules = [
            _make_rule("CTX-CONTAINS", PolicyAction.BLOCK,
                       field="intent", op="contains", value="exfiltrate")
        ]
        r = empty_engine.evaluate(0.1, {"intent": "exfiltrate_secrets"})
        assert r.action == PolicyAction.BLOCK

    def test_in_operator(self, empty_engine: PolicyEngine) -> None:
        empty_engine._rules = [
            _make_rule("CTX-IN", PolicyAction.ESCALATE,
                       field="verdict", op="in", value=["WARNING", "BLOCK"])
        ]
        r = empty_engine.evaluate(0.1, {"verdict": "WARNING"})
        assert r.action == PolicyAction.ESCALATE


class TestInvariants:
    def test_contestable_always_true(self, engine: PolicyEngine) -> None:
        for risk in [0.0, 0.5, 0.75, 0.95]:
            assert engine.evaluate(risk, {}).contestable is True

    def test_hmac_sha256_length(self, engine: PolicyEngine) -> None:
        r = engine.evaluate(0.5, {})
        assert len(r.hmac_tag) == 64

    def test_explain_not_empty_all_paths(self, engine: PolicyEngine) -> None:
        for risk in [0.0, 0.5, 0.75, 0.95]:
            r = engine.evaluate(risk, {})
            assert r.explain_decision() != ""

    def test_fail_secure_on_exception(self, engine: PolicyEngine) -> None:
        engine._rules = None  # type: ignore[assignment]
        r = engine.evaluate(0.5, {})
        assert r.action == PolicyAction.BLOCK
        assert r.contestable is True
        assert "FAIL_SECURE" in r.triggered_rules

    def test_sla_deadline_iso8601(self, engine: PolicyEngine) -> None:
        r = engine.evaluate(0.5, {})
        assert "T" in r.sla_deadline_iso and "+" in r.sla_deadline_iso or "Z" in r.sla_deadline_iso


# ── C15: ArtifactAllowlist ────────────────────────────────────────────────────

class TestArtifactAllowlist:
    def test_defaults_when_no_yaml(self, tmp_path: Path) -> None:
        # Empty directory — no artifact_allowlist.yaml
        engine = PolicyEngine(policies_dir=tmp_path)
        cfg = engine.artifact_allowlist
        assert isinstance(cfg, ArtifactAllowlistConfig)
        # require_artifact_allowlist=False by default (dev-mode compatible)
        assert cfg.require_artifact_allowlist is False
        assert cfg.allowlist_hash_algorithm == "blake3"
        # block_on_unknown_artifact=True by default (fail-secure)
        assert cfg.block_on_unknown_artifact is True

    def test_reads_from_yaml(self, tmp_path: Path) -> None:
        policy = {
            "governance": {
                "artifact_allowlist": {
                    "require_artifact_allowlist": True,
                    "allowlist_hash_algorithm": "sha256",
                    "block_on_unknown_artifact": False,
                }
            }
        }
        p = tmp_path / "artifact_allowlist.yaml"
        p.write_text(yaml.dump(policy))
        engine = PolicyEngine(policies_dir=tmp_path)
        cfg = engine.artifact_allowlist
        assert cfg.require_artifact_allowlist is True
        assert cfg.allowlist_hash_algorithm == "sha256"
        assert cfg.block_on_unknown_artifact is False

    def test_config_is_frozen(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policies_dir=tmp_path)
        cfg = engine.artifact_allowlist
        import dataclasses
        assert dataclasses.is_dataclass(cfg)
        # frozen=True: attribute assignment raises FrozenInstanceError
        import pytest
        with pytest.raises((TypeError, AttributeError)):
            cfg.require_artifact_allowlist = True  # type: ignore[misc]
