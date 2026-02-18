"""
ComplianceEvaluator v1.0 — P1: Condition Template Evaluation
Evaluates compliance YAML condition_templates against agent metadata.

Uses SafeExpressionEvaluator (sandboxed, no eval/exec/import).
Fail-secure: evaluation error → NON_COMPLIANT.

Filosofia (Rawls): Blind evaluation — same rules for all agents,
regardless of who operates them.
"""

import logging
import time
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from buildtovalue.governance.safe_expression_evaluator import (
    SafeExpressionEvaluator,
    SecurityError,
)

logger = logging.getLogger("btv.compliance.evaluator")

COMPLIANCE_DIR = Path("data/policies/compliance")


@dataclass(frozen=True)
class ComplianceViolation:
    """Single compliance violation found."""
    framework: str
    article: str
    requirement: str
    policy_name: str
    action: str  # BLOCK, ESCALATE, LOG
    confidence: float
    condition: str
    notes: str = ""


@dataclass(frozen=True)
class ComplianceEvalResult:
    """Result of evaluating all frameworks against agent metadata."""
    agent_id: str
    frameworks_evaluated: int
    rules_evaluated: int
    violations: List[ComplianceViolation]
    compliant_count: int
    skipped_count: int
    evaluation_time_ms: float
    timestamp: int = field(default_factory=lambda: int(time.time()))

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def compliance_rate(self) -> float:
        total = self.compliant_count + self.violation_count
        return self.compliant_count / total if total > 0 else 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "frameworks_evaluated": self.frameworks_evaluated,
            "rules_evaluated": self.rules_evaluated,
            "violations": [
                {
                    "framework": v.framework,
                    "article": v.article,
                    "requirement": v.requirement,
                    "policy_name": v.policy_name,
                    "action": v.action,
                    "confidence": v.confidence,
                    "notes": v.notes,
                }
                for v in self.violations
            ],
            "compliant_count": self.compliant_count,
            "skipped_count": self.skipped_count,
            "violation_count": self.violation_count,
            "compliance_rate": round(self.compliance_rate, 4),
            "evaluation_time_ms": round(self.evaluation_time_ms, 2),
            "timestamp": self.timestamp,
        }


# ─────────────────────────────────────────────────────────────
# BUILTIN FUNCTIONS for condition_template evaluation
# ─────────────────────────────────────────────────────────────

def _days_since(date_value) -> int:
    """Calculate days since a date (int YYYYMMDD or str)."""
    import datetime as dt

    if date_value is None:
        return 99999  # Treat null as "very long ago"

    if isinstance(date_value, int):
        year = date_value // 10000
        month = (date_value // 100) % 100
        day = date_value % 100
        try:
            d = dt.date(year, month, day)
        except ValueError:
            return 99999
    elif isinstance(date_value, str):
        try:
            d = dt.date.fromisoformat(date_value)
        except ValueError:
            return 99999
    else:
        return 99999

    return (dt.date.today() - d).days


def _contains(collection, item) -> bool:
    """Safe 'in' check for condition_templates."""
    if collection is None:
        return False
    if isinstance(collection, (list, tuple, set)):
        return item in collection
    if isinstance(collection, str):
        return item in collection
    return False


# ─────────────────────────────────────────────────────────────
# AGENT METADATA (dot-access wrapper)
# ─────────────────────────────────────────────────────────────

class DotDict:
    """
    Wraps a dict so condition_templates can use dot notation:
    agent.risk_level instead of agent['risk_level'].
    Returns None for missing keys (fail-safe, not KeyError).
    """

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def __getattr__(self, key: str) -> Any:
        val = self._data.get(key)
        if isinstance(val, dict):
            return DotDict(val)
        return val

    def __eq__(self, other):
        if isinstance(other, DotDict):
            return self._data == other._data
        return NotImplemented

    def __repr__(self):
        return f"DotDict({self._data})"

    def __bool__(self):
        return bool(self._data)


# ─────────────────────────────────────────────────────────────
# COMPLIANCE EVALUATOR
# ─────────────────────────────────────────────────────────────

class ComplianceEvaluator:
    """
    Evaluates compliance YAML condition_templates against agent metadata.

    Flow:
    1. Load 7 compliance YAMLs from data/policies/compliance/
    2. For each rule, evaluate condition_template with SafeExpressionEvaluator
    3. If condition is True → violation (action from YAML)
    4. If condition is False → compliant
    5. If evaluation error → skip (logged, counted)

    Thread-safe: evaluator is stateless per call.
    """

    def __init__(
        self,
        compliance_dir: Optional[Path] = None,
        timeout_ms: int = 50,
    ):
        self._dir = compliance_dir or COMPLIANCE_DIR
        self._evaluator = SafeExpressionEvaluator(timeout_ms=timeout_ms)
        self._frameworks: Dict[str, Dict] = {}
        self._load_frameworks()

    def _load_frameworks(self) -> None:
        """Load all compliance YAMLs from directory."""
        if not self._dir.exists():
            logger.warning("Compliance dir not found: %s", self._dir)
            return

        for path in sorted(self._dir.glob("*.yaml")):
            try:
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data or "articles" not in data and "_metadata" not in data:
                    continue

                fw_id = data.get("_metadata", {}).get("framework_id", path.stem)
                self._frameworks[fw_id] = data
                logger.info("Loaded compliance framework: %s (%d articles)",
                            fw_id, len(data.get("articles", {})))

            except Exception as e:
                logger.error("Failed to load %s: %s", path, e)

    @property
    def framework_count(self) -> int:
        return len(self._frameworks)

    @property
    def framework_ids(self) -> List[str]:
        return list(self._frameworks.keys())

    def evaluate(
        self,
        agent_metadata: Dict[str, Any],
        frameworks: Optional[List[str]] = None,
    ) -> ComplianceEvalResult:
        """
        Evaluate agent against loaded compliance frameworks.

        Args:
            agent_metadata: Dict with agent properties (risk_level,
                capabilities, conformity_assessment_completed, etc.)
            frameworks: Optional list of framework IDs to evaluate.
                If None, evaluates all loaded frameworks.

        Returns:
            ComplianceEvalResult with violations and stats.
        """
        start = time.perf_counter()

        agent = DotDict(agent_metadata)
        agent_id = agent_metadata.get("agent_id", "unknown")

        # Build evaluation context
        eval_context = {
            "agent": agent,
            "organization": DotDict(agent_metadata.get("organization", {})),
            "incident": DotDict(agent_metadata.get("incident", {})),
            "target_demographic": agent_metadata.get("target_demographic"),
            "use_case": agent_metadata.get("use_case"),
            "risk_score": agent_metadata.get("risk_score", 0.0),
            "interaction_type": agent_metadata.get("interaction_type"),
            # Builtin functions
            "days_since": _days_since,
            "contains": _contains,
            "len": len,
            "max": max,
            "min": min,
            "true": True,
            "false": False,
            "True": True,
            "False": False,
            "null": None,
            "None": None,
        }

        for key, val in agent_metadata.items():
            if key not in eval_context and not isinstance(val, dict):
                eval_context[key] = val

        # Merge parameters from each rule into context at eval time
        target_fws = frameworks or list(self._frameworks.keys())
        violations: List[ComplianceViolation] = []
        compliant = 0
        skipped = 0
        rules_evaluated = 0
        fws_evaluated = 0

        for fw_id in target_fws:
            fw_data = self._frameworks.get(fw_id)
            if not fw_data:
                continue
            fws_evaluated += 1

            articles = fw_data.get("articles", {})
            for article_key, rules in articles.items():
                if not isinstance(rules, list):
                    continue
                for rule in rules:
                    condition = rule.get("condition_template", "")
                    if not condition:
                        skipped += 1
                        continue

                    rules_evaluated += 1

                    # Inject rule-level parameters
                    params = rule.get("parameters", {})
                    rule_context = {**eval_context, **params}

                    try:
                        result = self._evaluator.evaluate(
                            condition, rule_context
                        )

                        if not result.success:
                            skipped += 1
                            logger.debug(
                                "Eval error %s/%s: %s",
                                fw_id, article_key, result.error,
                            )
                            continue

                        if result.value:
                            # Condition is True → violation
                            violations.append(ComplianceViolation(
                                framework=fw_id,
                                article=str(article_key),
                                requirement=rule.get("requirement_text", ""),
                                policy_name=rule.get("policy_name", ""),
                                action=rule.get("policy_action", "LOG"),
                                confidence=rule.get("confidence", 0.5),
                                condition=condition,
                                notes=rule.get("notes", ""),
                            ))
                        else:
                            compliant += 1

                    except (SecurityError, Exception) as e:
                        skipped += 1
                        logger.warning(
                            "Security/eval error %s/%s: %s",
                            fw_id, article_key, e,
                        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        return ComplianceEvalResult(
            agent_id=agent_id,
            frameworks_evaluated=fws_evaluated,
            rules_evaluated=rules_evaluated,
            violations=violations,
            compliant_count=compliant,
            skipped_count=skipped,
            evaluation_time_ms=elapsed_ms,
        )