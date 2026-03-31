"""
Testes ADR-036: BiasGuardian — API LEGADA.

Movido para _legacy em Sprint 5 (2026-03-09).
A API atual usa `check_eligibility` + `GuardianVerdict`, não `evaluate_report`.
Testes correntes: tests/unit/governance/test_bias_guardian.py

Estes testes estão desabilitados com pytest.skip para evitar falsos negativos
no CI enquanto a API antiga não for reimplementada ou removida oficialmente.
"""
import pytest

pytest.skip(
    "Legacy API (evaluate_report / GuardianResult / reports_dir) removed in Sprint 5. "
    "Current tests: tests/unit/governance/test_bias_guardian.py",
    allow_module_level=True,
)
