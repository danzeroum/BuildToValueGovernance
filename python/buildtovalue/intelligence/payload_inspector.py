"""
PayloadInspector - PROP-034 Stage 2 (Python Intelligence).

Orchestrates Stage 1 Rust InjectionSignal + SLMClassifier
for semantic inspection in the ambiguity zone.

Architecture (ADR-027):
  Stage 1 Rust  : zero-heap heuristics -> InjectionSignal
  Stage 2 Python: SLM semantic classification in ambiguity zone
  Output        : Finding, not a Verdict (Levinas: human can contest)
  Fail-open     : SLM failure -> inspection continues (no SLM finding)
  Fail-secure   : Confirmed   -> BLOCK immediately (Jonas)

Filosofia (Jonas): Data never leaves the perimeter (local SLM).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .slm_classifier import SLMClassifier, SLMClassification, IntentLabel


# ─────────────────────────────────────────────────────────────────────────────
# TYPES
# ─────────────────────────────────────────────────────────────────────────────

class InjectionSignal(str, Enum):
    """Mirrors Rust InjectionSignal (PROP-034 Stage 1)."""
    CLEAN     = "Clean"
    SUSPICIOUS = "Suspicious"
    CONFIRMED  = "Confirmed"


class InspectionAction(str, Enum):
    ALLOW   = "ALLOW"
    INSPECT = "INSPECT"   # forward to Judiciario with SLM finding
    BLOCK   = "BLOCK"


@dataclass(frozen=True)
class PayloadInspectionReport:
    """
    Resultado imutavel da inspecao de payload.

    explain_decision OBRIGATORIO (invariante arquitetural).
    slm_classification: None se SLM nao acionado ou falhou (fail-open).
    action: InspectionAction recomendada ao Judiciario.
    """
    action:             InspectionAction
    explain_decision:   str
    injection_signal:   InjectionSignal
    slm_classification: Optional[SLMClassification]
    payload_len:        int
    decided_at_iso:     str
    signature:          str

    def has_slm_finding(self) -> bool:
        return (
            self.slm_classification is not None
            and self.slm_classification.is_malicious
        )

    def to_finding_dict(self) -> dict:
        base = {
            "module":           "PAYLOAD_INSPECTOR",
            "injection_signal": self.injection_signal.value,
            "action":           self.action.value,
            "payload_len":      self.payload_len,
            "decided_at_iso":   self.decided_at_iso,
            "signature":        self.signature,
        }
        if self.slm_classification is not None:
            base["slm"] = self.slm_classification.to_finding_dict()
        return base


# ─────────────────────────────────────────────────────────────────────────────
# INSPECTOR
# ─────────────────────────────────────────────────────────────────────────────

class PayloadInspector:
    """
    Orchestrates Stage 1 signal + Stage 2 SLM for payload inspection.

    Fail-open  : SLM error -> INSPECT (not BLOCK) — Jonas: certeza antes de punir.
    Fail-secure: Confirmed -> BLOCK immediately, sem SLM.
    """

    def __init__(
        self,
        hmac_secret: bytes,
        slm: Optional[SLMClassifier] = None,
    ) -> None:
        if not hmac_secret:
            raise ValueError("hmac_secret nao pode ser vazio")
        self._secret = hmac_secret
        self._slm    = slm  # None = sem SLM; fail-open gerenciado em _run_slm

    def inspect(
        self,
        payload:        str,
        signal:         InjectionSignal,
        finding_count:  int = 0,
        critical_count: int = 0,
    ) -> PayloadInspectionReport:
        """Inspeciona payload. Fail-secure em Confirmed; fail-open em erro SLM."""
        try:
            return self._inspect_internal(payload, signal, finding_count, critical_count)
        except Exception as exc:
            return self._fail_open_report(payload, signal, str(exc))

    # ── Internal ─────────────────────────────────────────────────────────────

    def _inspect_internal(
        self,
        payload:        str,
        signal:         InjectionSignal,
        finding_count:  int,
        critical_count: int,
    ) -> PayloadInspectionReport:

        # Stage 1 Confirmed -> BLOCK imediato, sem SLM (Jonas)
        if signal == InjectionSignal.CONFIRMED:
            return self._confirmed_block(payload, signal)

        slm_result = self._run_slm(payload, signal, finding_count, critical_count)
        action     = self._decide_action(signal, slm_result)
        explain    = self._build_explain(signal, slm_result, action, finding_count)
        now        = datetime.now(timezone.utc).isoformat()
        return PayloadInspectionReport(
            action=action,
            explain_decision=explain,
            injection_signal=signal,
            slm_classification=slm_result,
            payload_len=len(payload),
            decided_at_iso=now,
            signature=self._sign(action, signal, now),
        )

    def _run_slm(
        self,
        payload:        str,
        signal:         InjectionSignal,
        finding_count:  int,
        critical_count: int,
    ) -> Optional[SLMClassification]:
        if self._slm is None:
            return None
        if signal == InjectionSignal.SUSPICIOUS:
            return self._slm.classify(payload)   # sempre aciona se suspeito
        # Clean: aciona apenas na zona de ambiguidade
        return self._slm.classify_if_ambiguous(payload, finding_count, critical_count)

    def _decide_action(
        self,
        signal:     InjectionSignal,
        slm_result: Optional[SLMClassification],
    ) -> InspectionAction:
        if signal == InjectionSignal.SUSPICIOUS and slm_result is None:
            return InspectionAction.INSPECT  # SLM indisponivel: encaminha ao Judiciario

        if slm_result is not None and slm_result.is_malicious:
            # Alta confianca semantica -> BLOCK; baixa -> INSPECT
            if slm_result.confidence >= 0.7:
                return InspectionAction.BLOCK
            return InspectionAction.INSPECT

        return InspectionAction.ALLOW

    def _confirmed_block(
        self, payload: str, signal: InjectionSignal
    ) -> PayloadInspectionReport:
        now     = datetime.now(timezone.utc).isoformat()
        explain = (
            "[PayloadInspector] BLOCK imediato.\n"
            "  InjectionSignal=Confirmed (Stage 1 Rust).\n"
            "  SLM nao acionado: injecao ja confirmada por heuristicas.\n"
            "  Jonas: certeza de dano exige resposta imediata.\n"
            "  Decisao contestavel via /api/v1/contestation (SLA 24h)."
        )
        return PayloadInspectionReport(
            action=InspectionAction.BLOCK,
            explain_decision=explain,
            injection_signal=signal,
            slm_classification=None,
            payload_len=len(payload),
            decided_at_iso=now,
            signature=self._sign(InspectionAction.BLOCK, signal, now),
        )

    def _fail_open_report(
        self, payload: str, signal: InjectionSignal, error: str
    ) -> PayloadInspectionReport:
        now     = datetime.now(timezone.utc).isoformat()
        explain = (
            "[PayloadInspector] FAIL-OPEN ativado.\n"
            f"  erro interno: {error}\n"
            "  Acao: INSPECT (Levinas: nao punir por falha do sistema).\n"
            "  Encaminhado ao Judiciario para decisao final."
        )
        return PayloadInspectionReport(
            action=InspectionAction.INSPECT,
            explain_decision=explain,
            injection_signal=signal,
            slm_classification=None,
            payload_len=len(payload),
            decided_at_iso=now,
            signature=self._sign(InspectionAction.INSPECT, signal, now),
        )

    def _build_explain(
        self,
        signal:     InjectionSignal,
        slm:        Optional[SLMClassification],
        action:     InspectionAction,
        finding_count: int,
    ) -> str:
        lines = [
            f"[PayloadInspector] signal={signal.value}  action={action.value}",
            f"  finding_count={finding_count}",
        ]
        if slm is not None:
            lines.append(
                f"  SLM: intent={slm.intent.value}  risk={slm.risk:.2f}"
                f"  confidence={slm.confidence:.2f}  latency={slm.latency_ms:.1f}ms"
            )
            bias = "FPR/FNR declarados via BiasDeclaration (ADR-010)."
            lines.append(f"  {bias}")
        else:
            lines.append("  SLM: nao acionado (fora da zona de ambiguidade ou indisponivel).")
        lines.append("  Decisao contestavel via /api/v1/contestation (SLA 24h — Rawls).")
        return "\n".join(lines)

    def _sign(
        self,
        action:  InspectionAction,
        signal:  InjectionSignal,
        decided: str,
    ) -> str:
        payload = json.dumps(
            {"action": action.value, "decided": decided, "signal": signal.value},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
