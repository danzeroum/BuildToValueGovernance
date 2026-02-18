"""
RiskClassifier v1.0 — EU AI Act Annex III Risk Classification (B1).

Classifies AI agents into risk levels based on sector, capabilities,
and deployment context per EU AI Act Art. 5-6 + Annex III.

Filosofia (Rawls): Same classification criteria for all agents.
Filosofia (Jonas): Higher risk = higher obligations.
"""

import logging
import yaml
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("btv.compliance.risk_classifier")

SECTORS_INDEX = Path(__file__).resolve().parent.parent.parent.parent / "data" / "policies" / "sectors" / "_index.yaml"


class RiskLevel(str, Enum):
    PROHIBITED = "PROHIBITED"
    HIGH_RISK = "HIGH_RISK"
    LIMITED_RISK = "LIMITED_RISK"
    MINIMAL_RISK = "MINIMAL_RISK"


# ─────────────────────────────────────────────────────────────
# PROHIBITED CAPABILITIES (Art. 5, in force since Feb 2025)
# ─────────────────────────────────────────────────────────────

PROHIBITED_CAPABILITIES = frozenset({
    "subliminal_manipulation",
    "social_scoring_public",
    "real_time_biometric_public",
    "emotion_recognition_workplace",
    "emotion_recognition_education",
    "predictive_policing_profiling",
    "untargeted_facial_scraping",
    "vulnerability_exploitation",
})

# ─────────────────────────────────────────────────────────────
# LIMITED RISK TRIGGERS (Art. 50 — transparency obligations)
# ─────────────────────────────────────────────────────────────

LIMITED_RISK_CAPABILITIES = frozenset({
    "chatbot",
    "deepfake_generation",
    "synthetic_content",
    "emotion_detection",
    "biometric_categorization",
})


@dataclass(frozen=True)
class RiskClassification:
    """Result of risk classification."""
    agent_id: str
    risk_level: RiskLevel
    sector: str
    reasons: List[str]
    obligations: List[str]
    annex_iii: bool
    prohibited_detected: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "risk_level": self.risk_level.value,
            "sector": self.sector,
            "reasons": self.reasons,
            "obligations": self.obligations,
            "annex_iii": self.annex_iii,
            "prohibited_detected": self.prohibited_detected,
        }


# ─────────────────────────────────────────────────────────────
# OBLIGATIONS PER RISK LEVEL
# ─────────────────────────────────────────────────────────────

OBLIGATIONS = {
    RiskLevel.PROHIBITED: [
        "System MUST NOT be deployed (Art. 5)",
        "Penalties: up to EUR 35M or 7% global turnover",
    ],
    RiskLevel.HIGH_RISK: [
        "Risk management system (Art. 9)",
        "Data governance (Art. 10)",
        "Technical documentation (Art. 11)",
        "Record-keeping / logging (Art. 12)",
        "Transparency to deployers (Art. 13)",
        "Human oversight mechanisms (Art. 14)",
        "Accuracy, robustness, cybersecurity (Art. 15)",
        "Conformity assessment before deployment (Art. 43)",
        "EU database registration (Art. 49)",
        "Fundamental Rights Impact Assessment (Art. 27)",
        "Penalties: up to EUR 15M or 3% global turnover",
    ],
    RiskLevel.LIMITED_RISK: [
        "Transparency: inform users they interact with AI (Art. 50)",
        "Label AI-generated content (Art. 50.2)",
        "Label deepfakes (Art. 50.4)",
    ],
    RiskLevel.MINIMAL_RISK: [
        "Voluntary codes of conduct (Art. 95)",
        "No mandatory obligations",
    ],
}


class RiskClassifier:
    """
    Classifies AI agents per EU AI Act risk tiers.

    Priority order (highest wins):
    1. PROHIBITED — any prohibited capability detected
    2. HIGH_RISK — Annex III sector + safety component
    3. LIMITED_RISK — transparency-triggering capabilities
    4. MINIMAL_RISK — default
    """

    def __init__(self, sectors_path: Optional[Path] = None):
        self._sectors: Dict[str, Dict] = {}
        self._load_sectors(sectors_path or SECTORS_INDEX)

    def _load_sectors(self, path: Path) -> None:
        if not path.exists():
            logger.warning("Sectors index not found: %s", path)
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self._sectors = data.get("sectors", {})
            logger.info(
                "Loaded %d sector mappings", len(self._sectors)
            )
        except Exception as e:
            logger.error("Failed to load sectors: %s", e)

    @property
    def sector_count(self) -> int:
        return len(self._sectors)

    def classify(
        self,
        agent_id: str,
        sector: str,
        capabilities: Optional[List[str]] = None,
        deployment_context: Optional[Dict[str, Any]] = None,
    ) -> RiskClassification:
        """
        Classify agent into EU AI Act risk tier.

        Args:
            agent_id: Unique agent identifier.
            sector: Sector ID (must match _index.yaml keys).
            capabilities: List of capability strings.
            deployment_context: Optional dict with additional context
                (e.g. safety_component, affects_fundamental_rights).
        """
        caps = set(capabilities or [])
        ctx = deployment_context or {}
        reasons: List[str] = []

        # ── 1. Check PROHIBITED (Art. 5) ─────────────────────
        prohibited_found = sorted(caps & PROHIBITED_CAPABILITIES)
        if prohibited_found:
            reasons.append(
                f"Prohibited capabilities: {', '.join(prohibited_found)}"
            )
            return RiskClassification(
                agent_id=agent_id,
                risk_level=RiskLevel.PROHIBITED,
                sector=sector,
                reasons=reasons,
                obligations=OBLIGATIONS[RiskLevel.PROHIBITED],
                annex_iii=False,
                prohibited_detected=prohibited_found,
            )

        # ── 2. Check HIGH_RISK (Art. 6 + Annex III) ──────────
        sector_info = self._sectors.get(sector, {})
        sector_risk = sector_info.get("risk_classification", "minimal_risk")
        is_annex_iii = sector_info.get("eu_ai_act_annex") == "III"
        is_safety = ctx.get("safety_component", False)
        affects_rights = ctx.get("affects_fundamental_rights", False)

        if sector_risk == "high_risk" or is_annex_iii:
            reasons.append(f"Sector '{sector}' is Annex III high-risk")
            return RiskClassification(
                agent_id=agent_id,
                risk_level=RiskLevel.HIGH_RISK,
                sector=sector,
                reasons=reasons,
                obligations=OBLIGATIONS[RiskLevel.HIGH_RISK],
                annex_iii=True,
            )

        if is_safety:
            reasons.append("Safety component of regulated product")
            return RiskClassification(
                agent_id=agent_id,
                risk_level=RiskLevel.HIGH_RISK,
                sector=sector,
                reasons=reasons,
                obligations=OBLIGATIONS[RiskLevel.HIGH_RISK],
                annex_iii=False,
            )

        if affects_rights:
            reasons.append("Affects fundamental rights")
            return RiskClassification(
                agent_id=agent_id,
                risk_level=RiskLevel.HIGH_RISK,
                sector=sector,
                reasons=reasons,
                obligations=OBLIGATIONS[RiskLevel.HIGH_RISK],
                annex_iii=False,
            )

        # ── 3. Check LIMITED_RISK (Art. 50) ───────────────────
        limited_found = sorted(caps & LIMITED_RISK_CAPABILITIES)
        if limited_found:
            reasons.append(
                f"Transparency-triggering: {', '.join(limited_found)}"
            )
            return RiskClassification(
                agent_id=agent_id,
                risk_level=RiskLevel.LIMITED_RISK,
                sector=sector,
                reasons=reasons,
                obligations=OBLIGATIONS[RiskLevel.LIMITED_RISK],
                annex_iii=False,
            )

        # ── 4. Default: MINIMAL_RISK ─────────────────────────
        reasons.append("No high-risk indicators detected")
        return RiskClassification(
            agent_id=agent_id,
            risk_level=RiskLevel.MINIMAL_RISK,
            sector=sector,
            reasons=reasons,
            obligations=OBLIGATIONS[RiskLevel.MINIMAL_RISK],
            annex_iii=False,
        )