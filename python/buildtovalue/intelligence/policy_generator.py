"""
Policy Generator v2.0
Generates YAML policy cards from classified threats.
"""

import yaml
from typing import List
from .threat_classifier import Classification


class PolicyGenerator:
    """Generates YAML policies from threat classifications."""

    def generate(self, classification: Classification) -> str:
        policy = {
            "id": f"auto-{classification.threat_type}-001",
            "name": f"Auto: {classification.threat_type.replace('_', ' ').title()}",
            "description": f"Auto-generated from threat intel ({classification.category})",
            "enabled": True,
            "priority": classification.severity * 10,
            "severity": self._severity_label(classification.severity),
            "conditions": {
                "threat_type": classification.threat_type,
                "min_severity": classification.severity,
            },
            "action": classification.recommended_action,
            "source": "intelligence_hub",
            "confidence": classification.confidence,
            "auto_generated": True,
        }
        return yaml.dump(policy, default_flow_style=False, sort_keys=False)

    def generate_batch(self, classifications: List[Classification]) -> str:
        policies = []
        for i, c in enumerate(classifications):
            policy = yaml.safe_load(self.generate(c))
            policy["id"] = f"auto-{c.threat_type}-{i+1:03d}"
            policies.append(policy)

        doc = {
            "version": "2.0",
            "metadata": {
                "name": "Auto-generated Threat Policies",
                "source": "Intelligence Hub",
                "auto_generated": True,
            },
            "policies": policies,
        }
        return yaml.dump(doc, default_flow_style=False, sort_keys=False)

    @staticmethod
    def _severity_label(severity: int) -> str:
        if severity >= 9:
            return "CRITICAL"
        if severity >= 7:
            return "HIGH"
        if severity >= 4:
            return "MEDIUM"
        return "LOW"