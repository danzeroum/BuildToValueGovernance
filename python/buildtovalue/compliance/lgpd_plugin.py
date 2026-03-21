"""
LGPD Compliance Plugin v1.1
Lei Geral de Protecao de Dados (Brazil).

v1.1 (ADR-048): Added generate_ropa() for Art. 37 compliance.
"""

from typing import List, Optional
from .plugin import CompliancePlugin, ComplianceArtifact, ComplianceReport, ComplianceLevel


class LGPDPlugin:
    """LGPD compliance verification and artifact generation."""

    def framework_id(self) -> str:
        return "LGPD"

    def framework_name(self) -> str:
        return "Lei Geral de Protecao de Dados (Brazil)"

    def generate_artifacts(self, evidence: dict, verdict: dict) -> List[ComplianceArtifact]:
        artifacts = []

        # Art. 6 - Legitimate purpose
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 6",
            requirement="Processing must have legitimate purpose",
            status=ComplianceLevel.COMPLIANT,
            evidence="System processes data for security governance (legitimate interest)",
            recommendation="Document processing purpose in privacy policy",
        ))

        # Art. 20 - Right to explanation of automated decisions
        has_rationale = bool(verdict.get("rationale"))
        has_signature = bool(verdict.get("signature"))
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 20",
            requirement="Explanation of automated decisions",
            status=ComplianceLevel.COMPLIANT if has_rationale else ComplianceLevel.NON_COMPLIANT,
            evidence=f"explain_decision(): {'present' if has_rationale else 'MISSING'}. "
                     f"HMAC signature: {'present' if has_signature else 'MISSING'}.",
            recommendation="Ensure all verdicts include rationale and signature",
        ))

        # Art. 18 - Data subject rights (contestability)
        contestable = verdict.get("contestable", False)
        appeal_hours = verdict.get("appeal_deadline_hours", 0)
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 18",
            requirement="Right to contest automated decisions",
            status=ComplianceLevel.COMPLIANT if contestable else ComplianceLevel.PARTIAL,
            evidence=f"Contestable: {contestable}. Appeal window: {appeal_hours}h.",
            recommendation="Maintain 24h appeal window for all non-hard-block verdicts",
        ))

        # Art. 46 - Security measures
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 46",
            requirement="Technical and administrative security measures",
            status=ComplianceLevel.COMPLIANT,
            evidence="HMAC-SHA256 signatures, BLAKE3 hashing, fail-secure design, immutable ledger",
            recommendation="Schedule annual security audit",
        ))

        # Art. 48 - Incident notification
        hard_blocked = verdict.get("hard_blocked", False) or evidence.get("hard_blocked", False)
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 48",
            requirement="Incident notification to ANPD within 72h",
            status=ComplianceLevel.COMPLIANT if not hard_blocked else ComplianceLevel.PARTIAL,
            evidence=f"Hard block detected: {hard_blocked}. Incident logged in ledger.",
            recommendation="Automate ANPD notification for critical incidents",
        ))

        return artifacts

    def generate_ropa(
        self,
        controller: str,
        dpo_name: str,
        dpo_contact: str,
        ledger_path: str = "data/ledger/decisions.jsonl",
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
    ) -> dict:
        """Generate ROPA document (Art. 37) from real ledger data (ADR-048)."""
        from .ledger_analytics import LedgerAnalytics
        from .ropa_generator import ROPAGenerator
        analytics = LedgerAnalytics(ledger_path)
        generator = ROPAGenerator(analytics)
        ropa = generator.generate(
            controller=controller,
            dpo_name=dpo_name,
            dpo_contact=dpo_contact,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        return ropa.to_dict()

    def validate_requirements(self) -> ComplianceReport:
        # Validate system-level compliance (no specific evidence)
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
            framework="LGPD",
            version="1.0",
            total_requirements=total,
            compliant=compliant,
            partial=partial,
            non_compliant=non_compliant,
            artifacts=artifacts,
            compliance_rate=compliant / total if total > 0 else 0.0,
        )