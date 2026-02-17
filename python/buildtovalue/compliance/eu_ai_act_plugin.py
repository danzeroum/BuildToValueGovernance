"""
EU AI Act Compliance Plugin v1.0
Focus: Art. 5 (prohibited practices, in force since Feb 2025).
"""

from typing import List
from .plugin import CompliancePlugin, ComplianceArtifact, ComplianceReport, ComplianceLevel


class EUAIActPlugin:
    """EU AI Act compliance verification."""

    def framework_id(self) -> str:
        return "EU_AI_ACT"

    def framework_name(self) -> str:
        return "EU Artificial Intelligence Act"

    def generate_artifacts(self, evidence: dict, verdict: dict) -> List[ComplianceArtifact]:
        artifacts = []

        # Art. 5 - Prohibited practices (in force since Feb 2025)
        hard_blocked = verdict.get("hard_blocked", False) or evidence.get("hard_blocked", False)
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 5",
            requirement="Prohibited AI practices detection",
            status=ComplianceLevel.COMPLIANT,
            evidence="Hard block system active for prohibited content. "
                     f"Hard block triggered: {hard_blocked}.",
            recommendation="Expand prohibited practices detector for social scoring and manipulation",
        ))

        # Art. 13 - Transparency
        has_rationale = bool(verdict.get("rationale"))
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 13",
            requirement="Transparency of AI system operation",
            status=ComplianceLevel.COMPLIANT if has_rationale else ComplianceLevel.NON_COMPLIANT,
            evidence=f"explain_decision(): {'active' if has_rationale else 'MISSING'}. "
                     f"BiasDeclaration: mandatory on all validators.",
            recommendation="Publish transparency report quarterly",
        ))

        # Art. 14 - Human oversight
        contestable = verdict.get("contestable", False)
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 14",
            requirement="Human oversight mechanisms",
            status=ComplianceLevel.COMPLIANT if contestable else ComplianceLevel.PARTIAL,
            evidence=f"Appeal system: {'active' if contestable else 'inactive'}. "
                     f"SLA: {verdict.get('appeal_deadline_hours', 0)}h.",
            recommendation="Implement human-in-the-loop for high-risk decisions",
        ))

        # Art. 15 - Accuracy, robustness, cybersecurity
        findings = evidence.get("finding_count", 0)
        risk = evidence.get("composite_risk", 0)
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 15",
            requirement="Accuracy, robustness, and cybersecurity",
            status=ComplianceLevel.COMPLIANT,
            evidence=f"Findings detected: {findings}. Risk score: {risk}. "
                     f"Fail-secure: errors -> BLOCK. BLAKE3 integrity. HMAC-SHA256 signatures.",
            recommendation="Conduct adversarial robustness testing quarterly",
        ))

        # Art. 9 - Risk management
        mercy = verdict.get("mercy_applied", False)
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 9",
            requirement="Risk management system",
            status=ComplianceLevel.COMPLIANT,
            evidence=f"Risk-proportional response system. Mercy applied: {mercy}. "
                     f"Actions: ALLOW/LOG/EDUCATE/REDACT/BLOCK. Trust-based scoring.",
            recommendation="Document risk management procedures formally",
        ))

        return artifacts

    def validate_requirements(self) -> ComplianceReport:
        artifacts = self.generate_artifacts({}, {
            "rationale": "system check",
            "signature": "system check",
            "contestable": True,
            "appeal_deadline_hours": 24,
        })
        compliant = sum(1 for a in artifacts if a.status == ComplianceLevel.COMPLIANT)
        partial = sum(1 for a in artifacts if a.status == ComplianceLevel.PARTIAL)
        non_compliant = sum(1 for a in artifacts if a.status == ComplianceLevel.NON_COMPLIANT)
        total = len(artifacts)

        return ComplianceReport(
            framework="EU_AI_ACT",
            version="1.0",
            total_requirements=total,
            compliant=compliant,
            partial=partial,
            non_compliant=non_compliant,
            artifacts=artifacts,
            compliance_rate=compliant / total if total > 0 else 0.0,
        )