"""
FRIA Generator v1.0 — Fundamental Rights Impact Assessment (EU AI Act Art. 27).

Generates structured FRIA documents for high-risk AI systems.
Auto-populates from RiskClassification + ComplianceEvalResult.

Filosofia (Rawls): Equal assessment criteria for all agents.
Filosofia (Jonas): Proportional documentation to risk level.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("btv.compliance.fria")


# ─────────────────────────────────────────────────────────────
# FRIA SECTIONS (EU AI Act Art. 27 requirements)
# ─────────────────────────────────────────────────────────────

@dataclass
class FRIASection:
    """Single section of the FRIA document."""
    section_id: str
    title: str
    question: str
    auto_answer: str
    manual_required: bool
    risk_indicator: str  # LOW, MEDIUM, HIGH, CRITICAL
    article_ref: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "section_id": self.section_id,
            "title": self.title,
            "question": self.question,
            "auto_answer": self.auto_answer,
            "manual_required": self.manual_required,
            "risk_indicator": self.risk_indicator,
            "article_ref": self.article_ref,
        }


@dataclass
class FRIADocument:
    """Complete FRIA document."""
    agent_id: str
    risk_level: str
    sector: str
    generated_at: str
    sections: List[FRIASection]
    summary: str
    total_sections: int
    auto_filled: int
    manual_pending: int
    overall_risk: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "risk_level": self.risk_level,
            "sector": self.sector,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "total_sections": self.total_sections,
            "auto_filled": self.auto_filled,
            "manual_pending": self.manual_pending,
            "overall_risk": self.overall_risk,
            "sections": [s.to_dict() for s in self.sections],
        }


class FRIAGenerator:
    """
    Generates Fundamental Rights Impact Assessments.

    Auto-populates answers from:
    - RiskClassification (sector, risk level, obligations)
    - ComplianceEvalResult (violations, compliance rate)
    - System capabilities (explain_decision, contestability, etc.)
    """

    def generate(
        self,
        agent_id: str,
        risk_level: str,
        sector: str,
        obligations: Optional[List[str]] = None,
        violations: Optional[List[Dict]] = None,
        compliance_rate: Optional[float] = None,
        capabilities: Optional[List[str]] = None,
    ) -> FRIADocument:
        obligs = obligations or []
        viols = violations or []
        caps = capabilities or []
        rate = compliance_rate if compliance_rate is not None else 1.0

        sections = [
            self._purpose_section(agent_id, sector, caps),
            self._data_section(sector),
            self._transparency_section(rate),
            self._human_oversight_section(obligs),
            self._non_discrimination_section(sector, viols),
            self._privacy_section(sector),
            self._environmental_section(),
            self._accountability_section(rate, viols),
            self._contestability_section(),
            self._mitigation_section(viols, risk_level),
        ]

        auto = sum(1 for s in sections if not s.manual_required)
        manual = sum(1 for s in sections if s.manual_required)
        overall = self._calc_overall_risk(sections)

        summary = (
            f"FRIA for agent '{agent_id}' in sector '{sector}' "
            f"(risk: {risk_level}). "
            f"{auto}/{len(sections)} sections auto-filled. "
            f"{manual} require manual review. "
            f"Overall fundamental rights risk: {overall}."
        )

        return FRIADocument(
            agent_id=agent_id,
            risk_level=risk_level,
            sector=sector,
            generated_at=datetime.now(timezone.utc).isoformat(),
            sections=sections,
            summary=summary,
            total_sections=len(sections),
            auto_filled=auto,
            manual_pending=manual,
            overall_risk=overall,
        )

    # ─────────────────────────────────────────────────────────
    # SECTION GENERATORS
    # ─────────────────────────────────────────────────────────

    def _purpose_section(
        self, agent_id: str, sector: str, caps: List[str],
    ) -> FRIASection:
        caps_str = ", ".join(caps) if caps else "not specified"
        return FRIASection(
            section_id="FRIA-1",
            title="Purpose and Intended Use",
            question=(
                "What is the intended purpose of this AI system "
                "and what decisions does it make or support?"
            ),
            auto_answer=(
                f"Agent '{agent_id}' operates in the '{sector}' sector. "
                f"Capabilities: {caps_str}. "
                "System is used for input validation, risk assessment, "
                "and governance enforcement under BuildToValue Trust OS."
            ),
            manual_required=True,
            risk_indicator="MEDIUM",
            article_ref="Art. 27.1",
        )

    def _data_section(self, sector: str) -> FRIASection:
        high_risk_data = sector in (
            "healthcare", "biometric", "law_enforcement",
            "employment", "education",
        )
        return FRIASection(
            section_id="FRIA-2",
            title="Data and Input Assessment",
            question=(
                "What personal data is processed? Are special "
                "categories of data involved (Art. 9 GDPR)?"
            ),
            auto_answer=(
                f"Sector '{sector}' — "
                f"{'likely processes special category data' if high_risk_data else 'standard data processing'}. "
                "BTV scans inputs for PII (CPF, CNPJ, email, phone, credit card). "
                "Detected PII is logged in immutable ledger. "
                "SLM classifier runs locally (zero data exfiltration)."
            ),
            manual_required=high_risk_data,
            risk_indicator="HIGH" if high_risk_data else "LOW",
            article_ref="Art. 27.1, GDPR Art. 9",
        )

    def _transparency_section(self, rate: float) -> FRIASection:
        return FRIASection(
            section_id="FRIA-3",
            title="Transparency and Explainability",
            question=(
                "How are affected persons informed about the AI "
                "system's operation and decisions?"
            ),
            auto_answer=(
                "Every decision includes explain_decision() with rationale. "
                "BiasDeclaration mandatory on all validators. "
                f"Current compliance rate: {rate:.0%}. "
                "Decisions are signed (HMAC-SHA256) for non-repudiation."
            ),
            manual_required=False,
            risk_indicator="LOW" if rate >= 0.8 else "MEDIUM",
            article_ref="Art. 13, Art. 27.1(c)",
        )

    def _human_oversight_section(self, obligs: List[str]) -> FRIASection:
        has_oversight = any("Art. 14" in o for o in obligs)
        return FRIASection(
            section_id="FRIA-4",
            title="Human Oversight",
            question=(
                "What human oversight mechanisms are in place? "
                "Can humans intervene or override AI decisions?"
            ),
            auto_answer=(
                "ContestabilityLoop: 24h SLA for human appeal review. "
                "All verdicts are contestable=true. "
                f"Art. 14 obligation: {'applicable' if has_oversight else 'not required'}. "
                "Appeals endpoint: POST /v1/appeals."
            ),
            manual_required=False,
            risk_indicator="LOW",
            article_ref="Art. 14, Art. 27.1(d)",
        )

    def _non_discrimination_section(
        self, sector: str, viols: List[Dict],
    ) -> FRIASection:
        bias_viols = [
            v for v in viols
            if "bias" in v.get("requirement", "").lower()
            or "discriminat" in v.get("requirement", "").lower()
        ]
        return FRIASection(
            section_id="FRIA-5",
            title="Non-Discrimination and Fairness",
            question=(
                "What measures ensure the AI system does not "
                "discriminate against protected groups?"
            ),
            auto_answer=(
                "BiasDeclaration on every validator (FPR, FNR, affected groups). "
                "Blind policy testing (Rawls). "
                f"Bias-related violations found: {len(bias_viols)}. "
                f"Sector '{sector}' safe patterns applied to reduce FPR."
            ),
            manual_required=len(bias_viols) > 0,
            risk_indicator="HIGH" if bias_viols else "MEDIUM",
            article_ref="Art. 27.1(e), Charter Art. 21",
        )

    def _privacy_section(self, sector: str) -> FRIASection:
        sensitive = sector in (
            "healthcare", "biometric", "law_enforcement",
        )
        return FRIASection(
            section_id="FRIA-6",
            title="Privacy and Data Protection",
            question=(
                "How is the right to privacy and data protection "
                "ensured (GDPR/LGPD)?"
            ),
            auto_answer=(
                "PII detection and masking (sanitize endpoint). "
                "SLM runs locally — zero data leaves perimeter (Jonas). "
                "Fail-secure: errors → BLOCK (never leak). "
                "Immutable ledger for audit trail."
            ),
            manual_required=sensitive,
            risk_indicator="HIGH" if sensitive else "LOW",
            article_ref="Art. 27.1(f), Charter Art. 7-8",
        )

    def _environmental_section(self) -> FRIASection:
        return FRIASection(
            section_id="FRIA-7",
            title="Environmental Impact",
            question=(
                "What is the environmental impact of the AI system?"
            ),
            auto_answer=(
                "SLM model: Qwen 2.5 3B (CPU-only, ~3GB RAM). "
                "No GPU required. Minimal energy footprint. "
                "Rust kernel optimized for low resource usage."
            ),
            manual_required=True,
            risk_indicator="LOW",
            article_ref="Art. 27.1(g)",
        )

    def _accountability_section(
        self, rate: float, viols: List[Dict],
    ) -> FRIASection:
        return FRIASection(
            section_id="FRIA-8",
            title="Accountability and Governance",
            question=(
                "Who is responsible for the AI system? "
                "What governance structures exist?"
            ),
            auto_answer=(
                "Every verdict signed with HMAC-SHA256 (non-repudiation). "
                "Immutable ledger with full decision history. "
                f"Compliance rate: {rate:.0%}. "
                f"Active violations: {len(viols)}. "
                "República Algorítmica: Legislative (Policy) → "
                "Executive (Rust) → Judiciary (Python) → Auditory (Ledger)."
            ),
            manual_required=False,
            risk_indicator="MEDIUM" if viols else "LOW",
            article_ref="Art. 27.1(h)",
        )

    def _contestability_section(self) -> FRIASection:
        return FRIASection(
            section_id="FRIA-9",
            title="Right to Contest and Remedy",
            question=(
                "How can affected persons contest AI decisions "
                "and seek remedy?"
            ),
            auto_answer=(
                "All verdicts: contestable=true, appeal_deadline=24h. "
                "ContestabilityLoop with SQLite persistence. "
                "Endpoints: POST /v1/appeals, GET /v1/appeals/{id}. "
                "Reviewer resolution: POST /v1/appeals/{id}/resolve. "
                "LGPD Art. 20 + EU AI Act Art. 14 compliant."
            ),
            manual_required=False,
            risk_indicator="LOW",
            article_ref="Art. 27.1(i), LGPD Art. 20",
        )

    def _mitigation_section(
        self, viols: List[Dict], risk_level: str,
    ) -> FRIASection:
        viol_summary = (
            "; ".join(
                f"{v.get('framework')}/{v.get('article')}"
                for v in viols[:5]
            )
            if viols else "none detected"
        )
        return FRIASection(
            section_id="FRIA-10",
            title="Risk Mitigation Measures",
            question=(
                "What measures are in place to mitigate identified "
                "risks to fundamental rights?"
            ),
            auto_answer=(
                f"Risk level: {risk_level}. "
                f"Active violations: {viol_summary}. "
                "Mitigations: fail-secure design, mercy algorithm "
                "(Gilligan), trust scoring, sector-aware risk adjustment, "
                "BiasDeclaration mandate, immutable audit trail."
            ),
            manual_required=len(viols) > 0,
            risk_indicator="HIGH" if risk_level == "PROHIBITED" else (
                "MEDIUM" if viols else "LOW"
            ),
            article_ref="Art. 27.2",
        )

    def _calc_overall_risk(self, sections: List[FRIASection]) -> str:
        indicators = [s.risk_indicator for s in sections]
        if "CRITICAL" in indicators:
            return "CRITICAL"
        high_count = indicators.count("HIGH")
        if high_count >= 3:
            return "HIGH"
        if high_count >= 1:
            return "MEDIUM"
        return "LOW"