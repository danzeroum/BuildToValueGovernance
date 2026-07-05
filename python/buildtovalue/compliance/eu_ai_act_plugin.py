"""
EU AI Act Compliance Plugin v1.1
Focus: Art. 5 (prohibited practices, in force since Feb 2025).

v1.1: status deixa de ser hard-coded COMPLIANT — cada artefato é derivado
dos dados de runtime realmente fornecidos em (evidence, verdict). Sem
dados → PARTIAL com justificativa explícita. Art. 14 nunca passa de
PARTIAL: contestação ex-post (appeals) não é supervisão humana em tempo
real. Este plugin avalia evidência de UMA decisão; não certifica
conformidade organizacional.
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

        # O scan rodou de fato sobre esta decisão? Sem evidência de runtime,
        # nenhum artigo pode ser marcado COMPLIANT.
        scan_ran = bool(evidence) or bool(verdict.get("action")) or "hard_blocked" in verdict

        # Art. 5 - Prohibited practices (in force since Feb 2025)
        hard_blocked = verdict.get("hard_blocked", False) or evidence.get("hard_blocked", False)
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 5",
            requirement="Prohibited AI practices detection",
            status=ComplianceLevel.COMPLIANT if scan_ran else ComplianceLevel.PARTIAL,
            evidence=(
                f"Scan de práticas proibidas executado nesta decisão. "
                f"Hard block triggered: {hard_blocked}."
                if scan_ran else
                "Sem evidência de runtime fornecida — detecção não demonstrada "
                "para esta decisão."
            ),
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
        # HONESTIDADE REGULATÓRIA: o AppealEngine é contestação EX-POST
        # (remédio), não supervisão humana em tempo real com capacidade de
        # intervir/parar a operação, que é o que o Art. 14 exige. Teto: PARTIAL.
        contestable = verdict.get("contestable", False)
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 14",
            requirement="Human oversight mechanisms",
            status=ComplianceLevel.PARTIAL if contestable else ComplianceLevel.NON_COMPLIANT,
            evidence=(
                f"Contestação ex-post via appeals (SLA {verdict.get('appeal_deadline_hours', 0)}h): "
                f"{'ativa' if contestable else 'inativa'}. Supervisão em tempo real "
                f"(intervenção/override durante a operação) NÃO implementada — "
                f"cobertura parcial do Art. 14."
            ),
            recommendation="Implement real-time human-in-the-loop (intervene/stop) for high-risk decisions",
        ))

        # Art. 15 - Accuracy, robustness, cybersecurity
        has_integrity = bool(verdict.get("signature")) or bool(evidence.get("blake3_hash"))
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 15",
            requirement="Accuracy, robustness, and cybersecurity",
            status=ComplianceLevel.PARTIAL if has_integrity else ComplianceLevel.NON_COMPLIANT,
            evidence=(
                f"Integridade evidenciada: {'sim' if has_integrity else 'NÃO'} "
                f"(BLAKE3/HMAC-SHA256). Fail-secure: errors -> BLOCK. "
                f"Acurácia e robustez adversarial NÃO são medidas em runtime — "
                f"exigem avaliação externa (cobertura parcial)."
            ),
            recommendation="Conduct adversarial robustness testing quarterly and publish accuracy metrics",
        ))

        # Art. 9 - Risk management
        has_risk_data = ("composite_risk" in evidence) or bool(verdict.get("action"))
        mercy = verdict.get("mercy_applied", False)
        artifacts.append(ComplianceArtifact(
            framework="EU_AI_ACT",
            article="Art. 9",
            requirement="Risk management system",
            status=ComplianceLevel.COMPLIANT if has_risk_data else ComplianceLevel.PARTIAL,
            evidence=(
                f"Resposta proporcional ao risco aplicada nesta decisão "
                f"(risk={evidence.get('composite_risk', 'n/a')}, mercy={mercy}). "
                f"Actions: ALLOW/LOG/EDUCATE/REDACT/BLOCK."
                if has_risk_data else
                "Sem dados de risco fornecidos — gestão de risco não demonstrada "
                "para esta decisão."
            ),
            recommendation="Document risk management procedures formally",
        ))

        return artifacts

    def validate_requirements(self) -> ComplianceReport:
        # Self-check SEM evidência de runtime: os status refletem a ausência
        # de dados (nada de verdict pré-fabricado — v1.0 injetava um dict
        # canned e o relatório saía sempre ~100% conforme).
        artifacts = self.generate_artifacts({}, {})
        compliant = sum(1 for a in artifacts if a.status == ComplianceLevel.COMPLIANT)
        partial = sum(1 for a in artifacts if a.status == ComplianceLevel.PARTIAL)
        non_compliant = sum(1 for a in artifacts if a.status == ComplianceLevel.NON_COMPLIANT)
        total = len(artifacts)

        return ComplianceReport(
            framework="EU_AI_ACT",
            version="1.1",
            total_requirements=total,
            compliant=compliant,
            partial=partial,
            non_compliant=non_compliant,
            artifacts=artifacts,
            compliance_rate=compliant / total if total > 0 else 0.0,
        )
