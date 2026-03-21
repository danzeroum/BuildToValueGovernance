"""
Art. 20 Report Generator v1.0 — Automated Decision Log (LGPD Art. 20, ADR-048).

Generates structured reports of automated decisions for LGPD Art. 20 compliance.
Art. 20 mandates that data subjects have the right to request review of decisions
made solely by automated means that affect their interests.

This report provides:
- Complete log of automated decisions in a time period
- Statistical summary of decision patterns
- Methodology description for transparency
- BiasDeclaration references for accountability

Filosofia (Rawls): Equal transparency for all decisions.
Filosofia (Levinas): Respeito ao direito de contestação.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .ledger_analytics import LedgerAnalytics, DecisionRecord

logger = logging.getLogger("btv.compliance.art20")


@dataclass
class Art20Summary:
    """Statistical summary of automated decisions."""
    total_decisions: int = 0
    automated_decisions: int = 0
    block_decisions: int = 0
    allow_decisions: int = 0
    educate_decisions: int = 0
    redact_decisions: int = 0
    mercy_applied: int = 0
    hard_blocks: int = 0
    avg_risk: float = 0.0
    avg_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_decisions": self.total_decisions,
            "automated_decisions": self.automated_decisions,
            "block_decisions": self.block_decisions,
            "allow_decisions": self.allow_decisions,
            "educate_decisions": self.educate_decisions,
            "redact_decisions": self.redact_decisions,
            "mercy_applied": self.mercy_applied,
            "hard_blocks": self.hard_blocks,
            "avg_risk": round(self.avg_risk, 4),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }


@dataclass
class Art20Report:
    """Complete Art. 20 automated decision report."""
    period_start: str
    period_end: str
    summary: Art20Summary
    decisions: List[Dict[str, Any]]
    methodology: str
    bias_declarations: List[Dict[str, Any]]
    generated_at: str
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_type": "LGPD_ART20_REPORT",
            "legal_basis": "LGPD Art. 20 — Direito a revisao de decisoes automatizadas",
            "version": self.version,
            "generated_at": self.generated_at,
            "period": {
                "start": self.period_start,
                "end": self.period_end,
            },
            "summary": self.summary.to_dict(),
            "methodology": self.methodology,
            "bias_declarations": self.bias_declarations,
            "decisions": self.decisions,
            "total_decisions_in_report": len(self.decisions),
        }


class Art20ReportGenerator:
    """
    Generates LGPD Art. 20 automated decision reports from ledger data.

    Usage:
        analytics = LedgerAnalytics("data/ledger/decisions.jsonl")
        generator = Art20ReportGenerator(analytics)
        report = generator.generate(start_ts=..., end_ts=...)
    """

    def __init__(self, analytics: LedgerAnalytics) -> None:
        self._analytics = analytics

    def generate(
        self,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        include_decisions: bool = True,
        max_decisions: int = 500,
    ) -> Art20Report:
        """Generate Art. 20 report from ledger data."""
        records = self._analytics.get_decision_records(
            start_ts=start_ts,
            end_ts=end_ts,
            limit=max_decisions if include_decisions else 0,
        )

        summary = self._build_summary(records)
        decisions = [r.to_dict() for r in records] if include_decisions else []
        methodology = self._build_methodology()
        bias_decls = self._build_bias_declarations()

        period_start = self._format_ts(start_ts) if start_ts else "inicio do ledger"
        period_end = self._format_ts(end_ts) if end_ts else "presente"

        return Art20Report(
            period_start=period_start,
            period_end=period_end,
            summary=summary,
            decisions=decisions,
            methodology=methodology,
            bias_declarations=bias_decls,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _build_summary(self, records: List[DecisionRecord]) -> Art20Summary:
        summary = Art20Summary()
        summary.total_decisions = len(records)
        summary.automated_decisions = len(records)  # All BTV decisions are automated

        total_risk = 0.0
        total_latency = 0.0

        for r in records:
            total_risk += r.risk
            total_latency += r.latency_ms

            if r.final_action == "BLOCK":
                summary.block_decisions += 1
            elif r.final_action == "ALLOW":
                summary.allow_decisions += 1
            elif r.final_action == "EDUCATE":
                summary.educate_decisions += 1
            elif r.final_action == "REDACT":
                summary.redact_decisions += 1

            if r.mercy:
                summary.mercy_applied += 1
            if r.hard_blocked:
                summary.hard_blocks += 1

        if records:
            summary.avg_risk = total_risk / len(records)
            summary.avg_latency_ms = total_latency / len(records)

        return summary

    def _build_methodology(self) -> str:
        return (
            "Todas as decisoes sao tomadas automaticamente pelo BuildToValue "
            "Governance OS usando o seguinte pipeline:\n\n"
            "1. DEOBFUSCACAO: Normalizacao do input (base64, hex, leetspeak)\n"
            "2. ANALISE ESTATISTICA: Entropia, z-score, char-ratio, deteccao de idioma\n"
            "3. VALIDACAO: 12+ validadores deterministicos (CPF, CNPJ, email, cartao, etc.)\n"
            "4. DETECCAO DE INJECAO: Heuristicas de 3 camadas + SLM semantico (ADR-027/028)\n"
            "5. MOTOR ETICO: EthicalContextEngine agrega risco, aplica mercy (Gilligan), "
            "gera rationale explicativo, assina com HMAC-SHA256\n"
            "6. CONTESTACAO: Todas as decisoes sao contestaveis via POST /v1/appeals "
            "(SLA 24h, Rawls)\n\n"
            "Todos os validadores incluem BiasDeclaration mandatoria (ADR-010) com "
            "FPR/FNR medidos em corpus de teste. O SLM local (Phi-4 Mini) roda "
            "sem exfiltracao de dados (Jonas)."
        )

    def _build_bias_declarations(self) -> List[Dict[str, Any]]:
        """Build bias declarations for all components."""
        return [
            {
                "component": "Heuristic Prompt Injection Detector",
                "adr": "ADR-028",
                "fpr": 0.08,
                "fnr": 0.18,
                "calibration": "OWASP LLM Top 10 + Tensor Trust",
                "limitations": "Semantic attacks without keywords may bypass",
            },
            {
                "component": "SLM Classifier (Phi-4 Mini)",
                "adr": "ADR-027",
                "fpr": "measured per deployment",
                "fnr": "measured per deployment",
                "calibration": "BiasDeclaration updated per eval_benchmark.py",
                "limitations": "Non-English speakers may experience higher FPR",
            },
            {
                "component": "PII Validators (CPF, CNPJ, Email, etc.)",
                "adr": "ADR-035",
                "fpr": "< 1% (deterministic)",
                "fnr": "Regex-only: cannot detect PII in natural language",
                "calibration": "Algorithmic (Mod11, Luhn)",
                "limitations": "Formato estrito — PII em texto livre nao detectado sem NER",
            },
        ]

    def _format_ts(self, ts: int) -> str:
        return datetime.fromtimestamp(ts / 1000, tz=timezone.utc).isoformat()
