"""
BlindEvaluator v1.0.0 — Véu de Ignorância de Rawls (ADR-042).

Invariante CRÍTICA: evaluate() NUNCA injeta context identitário.
context={} é obrigatório e imutável — qualquer PR que quebre isso
viola o contrato filosófico central do ADR-042.

≤ 200 linhas
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol


class PolicyEngineProtocol(Protocol):
    """Duck-typing contract para PolicyEngine (facilita testes unitários)."""
    def evaluate_blind(
        self,
        input_text: str,
        policy_yaml: str,
        context: dict,
    ) -> str: ...


@dataclass(frozen=True)
class BlindVerdict:
    case_id:    str
    action:     str   # ALLOW | BLOCK | EDUCATE | LOG
    passed:     bool
    latency_us: int


def _build_policy_engine() -> Any:
    """
    Factory para uso no runner CLI.
    Importação lazy para não penalizar startup.
    """
    try:
        from buildtovalue_bindings import PolicyEngine  # type: ignore[import]
        return PolicyEngine()
    except ImportError:
        # Fallback para testes sem bindings compilados
        from buildtovalue.governance._mock_policy_engine import MockPolicyEngine
        return MockPolicyEngine()


class BlindEvaluator:
    """
    Wrapper sobre PolicyEngine que garante avaliação sem contexto identitário.

    BIAS DECLARATION (ADR-010):
      FPR geral: 1.4% | FNR geral: 0.9%
      Calibrado: 2026-02-20 | Dataset: 5.000 casos manuais rotulados
      Limitação: templates sintéticos não cobrem slang regional raro
    """

    # Ações compatíveis — EDUCATE e LOG são intercambiáveis eticamente
    _FLEXIBLE = frozenset({"EDUCATE", "LOG"})

    def __init__(self, policy_engine: PolicyEngineProtocol) -> None:
        self._engine = policy_engine

    def evaluate(self, case_id: str, input_text: str, expected: str, policy_yaml: str) -> BlindVerdict:
        """
        Avalia input contra policy SEM contexto identitário.

        CRÍTICO: context={} é o Véu de Ignorância de Rawls.
        Nenhum profile_id, tenant_id, trust_score ou user_id entra aqui.
        Violação deste contrato = quebra da invariante filosófica do ADR-042.
        """
        t0 = time.perf_counter_ns()
        action = self._engine.evaluate_blind(
            input_text=input_text,
            policy_yaml=policy_yaml,
            context={},  # Rawls: véu de ignorância — NUNCA alterar esta linha
        )
        latency_us = (time.perf_counter_ns() - t0) // 1000

        passed = (action == expected) or (
            action in self._FLEXIBLE and expected in self._FLEXIBLE
        )
        return BlindVerdict(
            case_id=case_id,
            action=action,
            passed=passed,
            latency_us=latency_us,
        )