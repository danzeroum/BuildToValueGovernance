"""
ThreatPolicyBridge v2.1
Connects Intelligence Hub → PolicyEngine via auto-generated YAML policies.

Philosophy:
  Jonas: Known threats MUST generate proportional defenses.
  Rawls: Auto-generated policies are NEVER auto-activated (blind testing first).
  Levinas: Drafts, not sentences — the Other deserves due process.

ADR: 0023-threat-policy-bridge.md
"""

import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .misp_ingestor import MispIngestor, ThreatEvent
from .threat_classifier import Classification, ThreatClassifier
from .policy_generator import PolicyGenerator

logger = logging.getLogger("btv.intelligence.bridge")

MAX_POLICIES_PER_SYNC = 50
MIN_SEVERITY_FOR_GENERATION = 1


@dataclass(frozen=True)
class BridgeSyncResult:
    """Immutable result of a bridge sync operation."""

    synced_at: float
    threats_processed: int
    policies_generated: int
    policies_deduplicated: int
    policies_dir: str
    all_require_review: bool = True
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "synced_at": self.synced_at,
            "threats_processed": self.threats_processed,
            "policies_generated": self.policies_generated,
            "policies_deduplicated": self.policies_deduplicated,
            "policies_dir": self.policies_dir,
            "all_require_review": self.all_require_review,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class GeneratedPolicy:
    """A policy draft generated from threat intelligence."""

    policy_id: str
    threat_type: str
    severity: int
    action: str
    source_threat_id: str
    yaml_content: str
    requires_review: bool = True
    enabled: bool = False


class ThreatPolicyBridge:
    """
    Orchestrates the flow: Threats → Classification → Policy YAML.

    All generated policies are born disabled (enabled: false) and
    require human review before activation. This is non-negotiable
    (Rawls: no punishment without due process).
    """

    def __init__(
        self,
        ingestor: MispIngestor,
        classifier: Optional[ThreatClassifier] = None,
        generator: Optional[PolicyGenerator] = None,
        policies_dir: str = "data/policies/auto-generated",
    ) -> None:
        self._ingestor = ingestor
        self._classifier = classifier or ThreatClassifier()
        self._generator = generator or PolicyGenerator()
        self._policies_dir = Path(policies_dir)
        self._existing_policies: Dict[str, int] = {}
        self._last_sync: Optional[BridgeSyncResult] = None

        self._policies_dir.mkdir(parents=True, exist_ok=True)
        self._load_existing_policies()

    def _load_existing_policies(self) -> None:
        """Scan existing auto-generated policies for dedup."""
        self._existing_policies.clear()
        for path in self._policies_dir.glob("*.yaml"):
            try:
                with open(path) as f:
                    doc = yaml.safe_load(f)
                if doc and isinstance(doc, dict):
                    threat_type = doc.get("conditions", {}).get(
                        "threat_type", ""
                    )
                    severity = doc.get("conditions", {}).get(
                        "min_severity", 0
                    )
                    if threat_type:
                        self._existing_policies[threat_type] = max(
                            self._existing_policies.get(threat_type, 0),
                            severity,
                        )
            except Exception as exc:
                logger.warning("Failed to parse %s: %s", path, exc)

    def _should_generate(self, classification: Classification) -> bool:
        """
        Dedup: skip if existing policy covers same threat_type
        with equal or higher severity.
        """
        existing_sev = self._existing_policies.get(
            classification.threat_type, -1
        )
        return classification.severity > existing_sev

    def _action_for_severity(self, severity: int) -> str:
        """Map severity → enforcement action (Jonas: proportional)."""
        if severity >= 8:
            return "BLOCK"
        if severity >= 5:
            return "ESCALATE"
        return "MONITOR_ONLY"

    def _build_policy_dict(
        self,
        classification: Classification,
        threat_event: ThreatEvent,
    ) -> Dict:
        """Build the policy YAML dict with all required fields."""
        action = self._action_for_severity(classification.severity)
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

        return {
            "id": f"auto-{classification.threat_type}-{ts}",
            "name": (
                f"[DRAFT] Auto: "
                f"{classification.threat_type.replace('_', ' ').title()}"
            ),
            "description": (
                f"Auto-generated from threat intel. "
                f"Source: {threat_event.source}. "
                f"Category: {classification.category}. "
                f"Threat ID: {threat_event.id}."
            ),
            "enabled": False,
            "requires_review": True,
            "priority": classification.severity * 10,
            "severity": self._generator._severity_label(
                classification.severity
            ),
            "conditions": {
                "threat_type": classification.threat_type,
                "min_severity": classification.severity,
            },
            "action": action,
            "source": "intelligence_bridge",
            "confidence": classification.confidence,
            "auto_generated": True,
            "source_threat_id": threat_event.id,
            "generated_at": ts,
        }

    def _write_policy_atomic(
        self, policy_id: str, content: str
    ) -> Path:
        """Atomic write: temp file + rename (no partial files)."""
        target = self._policies_dir / f"{policy_id}.yaml"
        fd, tmp_path = tempfile.mkstemp(
            dir=self._policies_dir, suffix=".tmp"
        )
        try:
            os.write(fd, content.encode("utf-8"))
            os.close(fd)
            os.replace(tmp_path, target)
        except Exception:
            os.close(fd) if not os.get_inheritable(fd) else None
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
        return target

    def sync(
        self, min_severity: int = MIN_SEVERITY_FOR_GENERATION
    ) -> BridgeSyncResult:
        """
        Execute full sync: ingestor → classifier → generator → disk.

        Returns BridgeSyncResult with counts and errors.
        """
        errors: List[str] = []
        generated: List[GeneratedPolicy] = []

        events = self._ingestor.export_batch(limit=500)
        classifications = self._classifier.classify_batch(events)

        event_map: Dict[str, ThreatEvent] = {
            e.id: e for e in events
        }

        for classification in classifications:
            if len(generated) >= MAX_POLICIES_PER_SYNC:
                logger.warning(
                    "Circuit breaker: max %d policies per sync",
                    MAX_POLICIES_PER_SYNC,
                )
                break

            if classification.severity < min_severity:
                continue

            if not self._should_generate(classification):
                continue

            threat_event = event_map.get(
                classification.threat_type, None
            )

            # Match by iterating if direct key fails
            if threat_event is None:
                for ev in events:
                    if ev.threat_type == classification.threat_type:
                        threat_event = ev
                        break

            if threat_event is None:
                errors.append(
                    f"No event found for {classification.threat_type}"
                )
                continue

            policy_dict = self._build_policy_dict(
                classification, threat_event
            )
            yaml_content = yaml.dump(
                policy_dict, default_flow_style=False, sort_keys=False
            )

            try:
                self._write_policy_atomic(
                    policy_dict["id"], yaml_content
                )
                generated.append(
                    GeneratedPolicy(
                        policy_id=policy_dict["id"],
                        threat_type=classification.threat_type,
                        severity=classification.severity,
                        action=policy_dict["action"],
                        source_threat_id=threat_event.id,
                        yaml_content=yaml_content,
                    )
                )
                self._existing_policies[
                    classification.threat_type
                ] = classification.severity

            except Exception as exc:
                msg = (
                    f"Write failed for "
                    f"{classification.threat_type}: {exc}"
                )
                logger.error(msg)
                errors.append(msg)

        deduped = len(classifications) - len(generated) - len(errors)

        result = BridgeSyncResult(
            synced_at=time.time(),
            threats_processed=len(events),
            policies_generated=len(generated),
            policies_deduplicated=max(0, deduped),
            policies_dir=str(self._policies_dir),
            errors=errors,
        )

        self._last_sync = result

        logger.info(
            "Bridge sync: %d threats → %d policies (%d deduped, %d errors)",
            result.threats_processed,
            result.policies_generated,
            result.policies_deduplicated,
            len(errors),
        )

        return result

    @property
    def last_sync(self) -> Optional[BridgeSyncResult]:
        return self._last_sync

    def pending_review_count(self) -> int:
        """Count policies awaiting human review."""
        count = 0
        for path in self._policies_dir.glob("*.yaml"):
            try:
                with open(path) as f:
                    doc = yaml.safe_load(f)
                if doc and not doc.get("enabled", False):
                    count += 1
            except Exception:
                pass
        return count