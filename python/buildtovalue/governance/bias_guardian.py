"""
Bias Guardian v1.0.0 (ADR-036)

Valida BiasDeclarations declaradas nos validators contra medições reais
dos relatórios red-team. Gera alerta se divergência excede tolerância.

Filosofia (Jonas): BiasDeclaration falsa é falsidade auditável.
Filosofia (Rawls): Mesma tolerância para todos os módulos.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Tolerâncias (ADR-036) ────────────────────────────────────────────
FNR_WARNING_THRESHOLD_PP = 5.0   # +5pp → WARNING
FNR_BLOCK_THRESHOLD_PP   = 8.0  # +10pp → BLOCK (CI gate)
FPR_WARNING_THRESHOLD_PP = 3.0
FPR_BLOCK_THRESHOLD_PP   = 6.0


class DivergenceLevel(Enum):
    OK      = "OK"
    WARNING = "WARNING"
    BLOCK   = "BLOCK"   # falha o CI gate


@dataclass
class BiasEvaluation:
    script_id: str
    module: str
    declared_fnr_pct: float
    measured_fnr_pct: float
    declared_fpr_pct: float
    measured_fpr_pct: float
    fnr_divergence_pp: float
    fpr_divergence_pp: float
    level: DivergenceLevel
    recommendation: str

    @property
    def passed(self) -> bool:
        return self.level != DivergenceLevel.BLOCK


@dataclass
class GuardianResult:
    evaluations: list[BiasEvaluation]

    @property
    def passed(self) -> bool:
        return all(e.passed for e in self.evaluations)

    @property
    def blocks(self) -> list[BiasEvaluation]:
        return [e for e in self.evaluations if e.level == DivergenceLevel.BLOCK]

    @property
    def warnings(self) -> list[BiasEvaluation]:
        return [e for e in self.evaluations if e.level == DivergenceLevel.WARNING]


class BiasGuardian:
    """
    Lê relatórios JSON de ops/red-team/reports/ e avalia divergências
    entre BiasDeclaration declarada e métricas medidas.
    """

    # Mapa script_id → módulo (expandir conforme novos RTs)
    SCRIPT_MODULE_MAP: dict[str, str] = {
        "RT-001": "PromptInjection",
        "RT-010": "NhsNumber",
        "RT-011": "EuVat",
        "RT-012": "Iban",
    }

    def __init__(self, reports_dir: str | Path = "ops/red-team/reports") -> None:
        self.reports_dir = Path(reports_dir)

    def evaluate_report(self, report: dict) -> BiasEvaluation:
        script_id = report.get("script_id", "UNKNOWN")
        module = self.SCRIPT_MODULE_MAP.get(script_id, script_id)

        bc = report.get("bias_declaration_comparison", {})
        declared_fnr = float(bc.get("declared_fnr_pct", 0))
        declared_fpr = float(bc.get("declared_fpr_pct", 0))
        measured_fnr = float(bc.get("measured_bypass_rate_pct", 0))
        measured_fpr = float(bc.get("measured_fpr_pct", 0))

        fnr_div = measured_fnr - declared_fnr
        fpr_div = measured_fpr - declared_fpr

        level, recommendation = self._classify(fnr_div, fpr_div, module)

        return BiasEvaluation(
            script_id=script_id,
            module=module,
            declared_fnr_pct=declared_fnr,
            measured_fnr_pct=measured_fnr,
            declared_fpr_pct=declared_fpr,
            measured_fpr_pct=measured_fpr,
            fnr_divergence_pp=round(fnr_div, 2),
            fpr_divergence_pp=round(fpr_div, 2),
            level=level,
            recommendation=recommendation,
        )

    def _classify(
        self,
        fnr_div: float,
        fpr_div: float,
        module: str,
    ) -> tuple[DivergenceLevel, str]:
        if fnr_div >= FNR_BLOCK_THRESHOLD_PP or fpr_div >= FPR_BLOCK_THRESHOLD_PP:
            return (
                DivergenceLevel.BLOCK,
                f"Recalibrar BiasDeclaration de {module} — "
                f"divergência crítica (FNR +{fnr_div:.1f}pp / FPR +{fpr_div:.1f}pp). "
                "CI gate bloqueado até correção.",
            )
        if fnr_div >= FNR_WARNING_THRESHOLD_PP or fpr_div >= FPR_WARNING_THRESHOLD_PP:
            return (
                DivergenceLevel.WARNING,
                f"Atualizar BiasDeclaration de {module} — "
                f"divergência aceitável mas acima do esperado "
                f"(FNR +{fnr_div:.1f}pp / FPR +{fpr_div:.1f}pp).",
            )
        return DivergenceLevel.OK, "BiasDeclaration dentro da tolerância."

    def evaluate_latest(self) -> GuardianResult:
        """Avalia o relatório mais recente de cada script_id."""
        latest: dict[str, dict] = {}
        for path in sorted(self.reports_dir.glob("RT-*.json")):
            try:
                report = json.loads(path.read_text())
                sid = report.get("script_id", path.stem)
                latest[sid] = report
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping %s: %s", path, exc)

        return GuardianResult(
            evaluations=[self.evaluate_report(r) for r in latest.values()]
        )

    def evaluate_suite(self, reports_dir: Optional[Path] = None) -> GuardianResult:
        """Avalia todos os relatórios (para CI — usa evaluate_latest em prod)."""
        target = reports_dir or self.reports_dir
        evaluations = []
        for path in sorted(target.glob("RT-*.json")):
            try:
                report = json.loads(path.read_text())
                evaluations.append(self.evaluate_report(report))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping %s: %s", path, exc)
        return GuardianResult(evaluations=evaluations)

    def print_summary(self, result: GuardianResult) -> None:
        print("\n═══ Bias Guardian Report ═══")
        for e in result.evaluations:
            icon = {"OK": "✅", "WARNING": "⚠️ ", "BLOCK": "❌"}[e.level.value]
            print(
                f"  {icon} [{e.level.value:7s}] {e.script_id} ({e.module}) — "
                f"FNR {e.declared_fnr_pct:.1f}%→{e.measured_fnr_pct:.1f}% "
                f"(+{e.fnr_divergence_pp:.1f}pp) | "
                f"FPR {e.declared_fpr_pct:.1f}%→{e.measured_fpr_pct:.1f}% "
                f"(+{e.fpr_divergence_pp:.1f}pp)"
            )
            if e.level != DivergenceLevel.OK:
                print(f"    → {e.recommendation}")
        status = "PASSED" if result.passed else "BLOCKED"
        print(f"\n  Gate: {status} ({len(result.blocks)} blocks, {len(result.warnings)} warnings)")
        print("════════════════════════════\n")
