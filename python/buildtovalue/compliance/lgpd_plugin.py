"""
LGPD Compliance Plugin v1.2
Lei Geral de Protecao de Dados (Brazil).

v1.1 (ADR-048): Added generate_ropa() for Art. 37 compliance.
v1.2: status derivado dos dados reais (fim do COMPLIANT hard-coded);
      Art. 48 tem teto PARTIAL (sem pipeline de notificação à ANPD).
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
        # Finalidade legítima é um fato organizacional — um sistema runtime
        # não pode verificá-la, apenas registrar a autodeclaração.
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 6",
            requirement="Processing must have legitimate purpose",
            status=ComplianceLevel.PARTIAL,
            evidence="Finalidade autodeclarada (governança de segurança / legítimo "
                     "interesse) — não verificável em runtime; exige documentação "
                     "organizacional.",
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
        # COMPLIANT só quando a decisão traz prova de integridade real.
        has_integrity = bool(verdict.get("signature")) or bool(evidence.get("blake3_hash"))
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 46",
            requirement="Technical and administrative security measures",
            status=ComplianceLevel.COMPLIANT if has_integrity else ComplianceLevel.PARTIAL,
            evidence=f"Prova de integridade nesta decisão: "
                     f"{'presente (HMAC-SHA256/BLAKE3)' if has_integrity else 'AUSENTE'}. "
                     f"Design fail-secure e ledger imutável no sistema.",
            recommendation="Schedule annual security audit",
        ))

        # Art. 48 - Incident notification
        # HONESTIDADE: não existe pipeline de notificação automática à ANPD.
        # O incidente é registrado no ledger; a notificação é processo manual
        # da organização. Teto: PARTIAL (nunca COMPLIANT via runtime).
        hard_blocked = verdict.get("hard_blocked", False) or evidence.get("hard_blocked", False)
        artifacts.append(ComplianceArtifact(
            framework="LGPD",
            article="Art. 48",
            requirement="Incident notification to ANPD within 72h",
            status=ComplianceLevel.PARTIAL,
            evidence=f"Hard block detected: {hard_blocked}. Incidente registrado no "
                     f"ledger; notificação automática à ANPD NÃO implementada — "
                     f"processo manual da organização.",
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
        # Self-check SEM evidência de runtime: os status refletem a ausência
        # de dados (a versão anterior injetava um verdict pré-fabricado e o
        # relatório saía sempre ~100% conforme — falsa segurança).
        artifacts = self.generate_artifacts({}, {})
        compliant = sum(1 for a in artifacts if a.status == ComplianceLevel.COMPLIANT)
        partial = sum(1 for a in artifacts if a.status == ComplianceLevel.PARTIAL)
        non_compliant = sum(1 for a in artifacts if a.status == ComplianceLevel.NON_COMPLIANT)
        total = len(artifacts)

        return ComplianceReport(
            framework="LGPD",
            version="1.2",
            total_requirements=total,
            compliant=compliant,
            partial=partial,
            non_compliant=non_compliant,
            artifacts=artifacts,
            compliance_rate=compliant / total if total > 0 else 0.0,
        )