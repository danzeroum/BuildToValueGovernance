"""
MercyFactor v1.0.0 — Gilligan's Ethics of Care.
Determines whether mercy should soften a decision.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger("btv.governance.mercy_factor")


@dataclass
class MercyFactor:
    """
    Mercy evaluation (Gilligan).

    Conditions for mercy:
    - High technical uncertainty (> 0.7)
    - First offense
    - High trust score (> 0.7)
    - Low violation severity (< 0.4)

    Mercy NEVER escalates severity.
    """
    technical_uncertainty: float = 0.0
    first_offense: bool = True
    trust_score: float = 0.5
    violation_severity: float = 0.0
    should_apply_mercy: bool = False
    mercy_adjustment: float = 0.0
    rationale: str = ""

    def calculate(self) -> "MercyFactor":
        """Calculate mercy factor. Returns self for chaining."""
        reasons: list[str] = []
        adjustment = 0.0

        if self.technical_uncertainty > 0.7:
            adjustment += 0.3
            reasons.append(
                f"alta incerteza tecnica ({self.technical_uncertainty:.2f})"
            )

        if self.first_offense:
            adjustment += 0.2
            reasons.append("primeira ofensa")

        if self.trust_score > 0.7:
            adjustment += 0.3
            reasons.append(f"alto trust score ({self.trust_score:.2f})")

        if self.violation_severity < 0.4:
            adjustment += 0.2
            reasons.append(f"baixa severidade ({self.violation_severity:.2f})")

        self.should_apply_mercy = adjustment >= 0.4
        self.mercy_adjustment = min(adjustment, 0.6)

        if self.should_apply_mercy:
            self.rationale = f"Misericordia aplicada: {', '.join(reasons)}"
            logger.info(self.rationale)
        else:
            self.rationale = "Misericordia nao aplicavel"

        return self