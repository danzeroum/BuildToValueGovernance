#!/usr/bin/env python3
"""
bias_guardian_gate.py — CI gate BiasDeclaration (ADR-036).

Exit 0  OK ou WARNING  — merge permitido (WARNING: label bias-update-required)
Exit 1  BLOCK          — merge impedido, divergencia critica (Jonas)

Prerequisito: ops/red-team/reports/*.json com schema_version 2.0.
Executar apos run-all.sh.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from buildtovalue.governance.bias_guardian import BiasGuardian, DivergenceLevel

REPORTS_DIR = Path(__file__).parent / "reports"
SEP = "═" * 56


def _icon(level: DivergenceLevel) -> str:
    return {"OK": "✅", "WARNING": "⚠️ ", "BLOCK": "🚫"}[level.value]


def main() -> int:
    if not REPORTS_DIR.exists() or not list(REPORTS_DIR.glob("RT-*.json")):
        print(f"WARN: {REPORTS_DIR} vazio — suite nao executada.", file=sys.stderr)
        return 0  # fail-open: CI sem red-team configurado nao bloqueia

    guardian = BiasGuardian(REPORTS_DIR)
    result = guardian.evaluate_suite()

    print(f"\n{SEP}")
    print("  BIAS GUARDIAN GATE  —  ADR-036")
    print(SEP)
    print(result.explain_decision())
    print()

    for mr in sorted(result.module_reports, key=lambda m: m.module_id):
        print(
            f"  {_icon(mr.divergence_level)} {mr.module_id}: "
            f"FNR Δ{mr.fnr_divergence_pp:+.1f}pp | FPR Δ{mr.fpr_divergence_pp:+.1f}pp"
        )
        if mr.violation_reason:
            print(f"       ↳ {mr.violation_reason}")
        if mr.recommended_fnr is not None:
            print(f"       ↳ Recomendado: FNR={mr.recommended_fnr}% FPR={mr.recommended_fpr}%")

    print(SEP)

    if result.overall_level == DivergenceLevel.BLOCK:
        print(
            "\n❌ GATE BLOQUEADO — BiasDeclaration critica. "
            "Atualizar antes do merge (Jonas: responsabilidade proporcional).\n"
        )
        return 1

    if result.overall_level == DivergenceLevel.WARNING:
        print("\n⚠️  GATE APROVADO COM AVISO — aplicar label 'bias-update-required'.\n")
        for mod in result.warning_modules:
            mr = next(m for m in result.module_reports if m.module_id == mod)
            reason = mr.violation_reason or "divergencia acima de 5pp"
            print(f"::warning title=BiasDeclaration Desatualizada::{mod} — {reason}")
        return 0

    print(
        "\n✅ GATE APROVADO — todas as BiasDeclarations dentro da tolerancia "
        "(Rawls: mesmo criterio para todos os modulos).\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
