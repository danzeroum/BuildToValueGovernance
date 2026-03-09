"""
context_engine_explain.py — explain_decision e Differential Privacy.
Extraído de context_engine.py (T1.3 — DT-005).

Filosofia:
  Levinas: explain_decision() obrigatório — transparência não negociável.
  Jonas: dp_noise evita engenharia reversa do modelo de risco.
"""
from __future__ import annotations

import math
import random

from .context_engine_types import RustEvidence, RequestContext
from .mercy_scenarios import MercyScenarioResult


def dp_noise(
    value: float,
    sensitivity: float = 0.1,
    epsilon: float = 1.0,
) -> float:
    """Mecanismo de Laplace para Differential Privacy (ADR-038 + Art.16).

    Adiciona ruído calibrado nos scores REPORTADOS na explicação.
    NÃO afeta scores usados na decisão — apenas o que é exibido ao usuário.
    scale = sensitivity / epsilon = 0.1 / 1.0 = 0.1
    """
    scale = sensitivity / epsilon
    u = random.random() - 0.5
    noise = -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u) + 1e-10)
    return max(0.0, min(1.0, round(value + noise, 2)))


def explain_decision(
    evidence: RustEvidence,
    context: RequestContext,
    trust: float,
    mercy_score: float,
    scenario: MercyScenarioResult,
    final_action: str,
    report_threshold: float,
) -> str:
    """Gera explicação legível (obrigatório — Levinas).

    Aplica ruído Laplace nos scores reportados para proteger o modelo de risco.
    A decisão em si NÃO é afetada.
    """
    r_risk    = dp_noise(evidence.composite_risk)
    r_trust   = dp_noise(trust)
    r_mercy   = dp_noise(mercy_score)
    r_entropy = dp_noise(evidence.entropy)

    parts = [
        f"Evidence: {evidence.finding_count} findings, "
        f"{evidence.critical_count} critical, "
        f"risk={r_risk:.2f}, entropy={r_entropy:.2f}.",

        f"Context: domain={context.domain}, role={context.user_role}, "
        f"ip_risk={context.ip_risk}, drift={context.drift_level}.",

        f"Trust: {r_trust:.2f}. Mercy: {r_mercy:.2f}.",

        f"Policy recommended: {evidence.policy_action}.",
    ]

    if scenario.mercy_applied:
        parts.append(
            f"Mercy applied ({scenario.scenario_id}): "
            f"{scenario.original_action} \u2192 {scenario.final_action} "
            f"(downgrade {scenario.downgrade_levels}). "
            f"{scenario.rationale}"
        )
    else:
        parts.append(
            f"No mercy applied ({scenario.scenario_id}). {scenario.rationale}"
        )

    if final_action != scenario.final_action:
        parts.append(
            f"Risk override: {scenario.final_action} \u2192 {final_action} "
            f"(ip_risk={context.ip_risk}, drift={context.drift_level})."
        )

    if final_action == "REPORT":
        parts.append(
            f"REPORT emitido: risco={evidence.composite_risk:.2f} >= threshold={report_threshold:.2f}. "
            "Output não alterado. Encaminhado para revisão humana (SLA 24h)."
        )

    parts.append(f"Final action: {final_action}. Contestable within 24h.")
    return " ".join(parts)
