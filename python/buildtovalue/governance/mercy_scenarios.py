"""
Mercy Scenarios v1.8.0 — 6 calibrated gradual mercy scenarios (Gilligan).

Each scenario defines:
- Conditions to match
- Downgrade levels (0, 1, or 2 severity levels)
- Rationale (for explain_decision)

Action severity ladder: BLOCK(4) → REDACT(3) → EDUCATE(2) → LOG(1) → ALLOW(0)
Downgrade 1: BLOCK→REDACT, REDACT→EDUCATE, etc.
Downgrade 2: BLOCK→EDUCATE, REDACT→LOG, etc.

Filosofia (Gilligan): Context > Rule. Care > Punishment.
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("btv.mercy.scenarios")

ACTION_SEVERITY = {
    "ALLOW": 0, "LOG": 1, "EDUCATE": 2, "REDACT": 3, "BLOCK": 4,
}
SEVERITY_ACTION = {v: k for k, v in ACTION_SEVERITY.items()}


@dataclass(frozen=True)
class MercyScenarioResult:
    """Result of applying mercy scenarios."""
    original_action: str
    final_action: str
    downgrade_levels: int
    scenario_id: str
    rationale: str
    mercy_score: float

    @property
    def mercy_applied(self) -> bool:
        return self.downgrade_levels > 0


def downgrade_action(action: str, levels: int) -> str:
    """Downgrade action by N severity levels. Floor is ALLOW."""
    severity = ACTION_SEVERITY.get(action, 4)
    new_severity = max(0, severity - levels)
    return SEVERITY_ACTION.get(new_severity, "ALLOW")


def evaluate_scenarios(
    action: str,
    mercy_score: float,
    trust_score: float,
    finding_count: int,
    critical_count: int,
    composite_risk: float,
    domain: str = "general",
    is_first_offense: bool = True,
) -> MercyScenarioResult:
    """
    Evaluate 6 calibrated mercy scenarios in priority order.
    First matching scenario wins.

    Returns MercyScenarioResult with downgrade applied.
    """

    # ── S1: CRITICAL OVERRIDE — never show mercy ──────────
    # Hard blocks, 2+ critical findings, or composite_risk >= 0.9
    if critical_count >= 2 or composite_risk >= 0.9:
        return MercyScenarioResult(
            original_action=action,
            final_action=action,
            downgrade_levels=0,
            scenario_id="S1_CRITICAL_OVERRIDE",
            rationale="Múltiplos findings críticos ou risco extremo. "
                      "Misericórdia não aplicável (Levinas: dever de proteção).",
            mercy_score=mercy_score,
        )

    # ── S2: HIGH TRUST VETERAN — downgrade 2 levels ──────
    # Trust >= 0.8, mercy >= 0.7, first offense, no criticals
    if (trust_score >= 0.8
            and mercy_score >= 0.7
            and is_first_offense
            and critical_count == 0):
        return MercyScenarioResult(
            original_action=action,
            final_action=downgrade_action(action, 2),
            downgrade_levels=2,
            scenario_id="S2_HIGH_TRUST_VETERAN",
            rationale="Usuário de alta confiança, primeira ocorrência, "
                      "sem findings críticos. Abrandamento forte "
                      "(Gilligan: relacionamento de cuidado).",
            mercy_score=mercy_score,
        )

    # ── S3: MEDICAL/RESEARCH CONTEXT — downgrade 1 level ─
    # Domain in (medical, research, legal), mercy >= 0.5
    if domain in ("medical", "research", "legal") and mercy_score >= 0.5:
        return MercyScenarioResult(
            original_action=action,
            final_action=downgrade_action(action, 1),
            downgrade_levels=1,
            scenario_id="S3_DOMAIN_CONTEXT",
            rationale=f"Domínio '{domain}' justifica flexibilidade. "
                      "PII pode ser necessário no contexto profissional "
                      "(Gilligan: contexto > regra abstrata).",
            mercy_score=mercy_score,
        )

    # ── S4: UNCERTAIN DETECTION — downgrade 1 level ──────
    # High uncertainty (mercy >= 0.6), low findings, first offense
    if (mercy_score >= 0.6
            and finding_count <= 2
            and is_first_offense
            and critical_count == 0
            and action not in ("ALLOW", "LOG")):  # ADR-043 fix
        return MercyScenarioResult(
            original_action=action,
            final_action=downgrade_action(action, 1),
            downgrade_levels=1,
            scenario_id="S4_UNCERTAIN_DETECTION",
            rationale="Detecção incerta (poucos findings, baixa confiança). "
                      "Educar antes de punir "
                      "(Levinas: benefício da dúvida).",
            mercy_score=mercy_score,
        )

    # ── S5: REPEAT OFFENDER LENIENCY — downgrade 1 level ─
    # Not first offense BUT trust still >= 0.5 and mercy >= 0.5
    if (not is_first_offense
            and trust_score >= 0.5
            and mercy_score >= 0.5
            and critical_count == 0):
        return MercyScenarioResult(
            original_action=action,
            final_action=downgrade_action(action, 1),
            downgrade_levels=1,
            scenario_id="S5_REPEAT_LENIENCY",
            rationale="Reincidente mas com trust razoável. "
                      "Manter educação, não punição "
                      "(Gilligan: preservar relacionamento).",
            mercy_score=mercy_score,
        )

    # ── S6: DEFAULT — no mercy ────────────────────────────
    # None of the above matched
    return MercyScenarioResult(
        original_action=action,
        final_action=action,
        downgrade_levels=0,
        scenario_id="S6_DEFAULT_NO_MERCY",
        rationale="Nenhum cenário de misericórdia aplicável. "
                  "Ação original mantida.",
        mercy_score=mercy_score,
    )