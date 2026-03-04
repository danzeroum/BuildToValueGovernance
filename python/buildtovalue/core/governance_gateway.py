"""
GovernanceGateway - Ponto de entrada unificado do Judiciario.

Pipeline:
  1. ContextSanitizer   -> sanitiza RequestContext (PROP-033)
  2. PayloadInspector   -> inspeciona payload / SLM  (PROP-034 Stage 2)
  3. EthicalContextEngine -> veredicto etico assinado
  4. GatewayVerdict     -> agrega tudo, HMAC-SHA256, explain_decision

Fail-secure: qualquer excecao interna -> BLOCK assinado.
Fail-open:   SLM ausente/falha -> pipeline continua (INSPECT ao Judiciario).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import uuid

from ..governance.context_engine import EthicalContextEngine, RustEvidence, RequestContext
from ..governance.context_sanitizer import ContextSanitizer, SanitizationLevel, SanitizationReport
from ..intelligence.payload_inspector import (
    PayloadInspector, InjectionSignal, InspectionAction, PayloadInspectionReport,
)
from ..governance.context_engine import EthicalVerdict


# ─────────────────────────────────────────────────────────────────────────────
# VERDICT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class GatewayVerdict:
    """
    Veredicto final agregado do GovernanceGateway.

    explain_decision agrega os 3 estagios.
    blocked_at: qual estagio causou o BLOCK (None se ALLOW).
    signature  : HMAC-SHA256 sobre action + verdict_id + decided_at.
    """
    verdict_id:         str
    action:             str          # ALLOW | BLOCK | INSPECT | REDACT | EDUCATE | LOG
    explain_decision:   str
    blocked_at:         Optional[str]  # "sanitizer" | "inspector" | "judiciario" | "fail_secure"
    sanitization_level: str
    inspection_action:  str
    ethical_action:     Optional[str]
    decided_at_iso:     str
    signature:          str
    contestable:        bool = True
    metadata:           dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "verdict_id":         self.verdict_id,
            "action":             self.action,
            "explain_decision":   self.explain_decision,
            "blocked_at":         self.blocked_at,
            "sanitization_level": self.sanitization_level,
            "inspection_action":  self.inspection_action,
            "ethical_action":     self.ethical_action,
            "decided_at_iso":     self.decided_at_iso,
            "signature":          self.signature,
            "contestable":        self.contestable,
            "metadata":           self.metadata,
        }


# ─────────────────────────────────────────────────────────────────────────────
# GATEWAY
# ─────────────────────────────────────────────────────────────────────────────

class GovernanceGateway:
    """
    Ponto de entrada unificado: sanitizacao -> inspecao -> veredicto etico.

    Invariantes:
    - explain_decision sempre presente (Levinas)
    - HMAC-SHA256 em todo veredicto (Jonas)
    - Fail-secure: excecao -> BLOCK (Jonas > eficiencia)
    - Contestable sempre True (Rawls: direito de contestar)
    """

    def __init__(
        self,
        hmac_secret:     bytes,
        ethical_engine:  EthicalContextEngine,
        sanitizer:       Optional[ContextSanitizer]  = None,
        inspector:       Optional[PayloadInspector]  = None,
    ) -> None:
        if not hmac_secret:
            raise ValueError("hmac_secret nao pode ser vazio")
        self._secret  = hmac_secret
        self._engine  = ethical_engine
        self._san     = sanitizer or ContextSanitizer(hmac_secret)
        self._insp    = inspector or PayloadInspector(hmac_secret)

    def evaluate(
        self,
        payload:        str,
        ctx:            RequestContext,
        evidence:       RustEvidence,
        signal:         InjectionSignal = InjectionSignal.CLEAN,
        finding_count:  int = 0,
        critical_count: int = 0,
    ) -> GatewayVerdict:
        """Pipeline completo. Fail-secure: excecao -> BLOCK assinado."""
        try:
            return self._evaluate_internal(
                payload, ctx, evidence, signal, finding_count, critical_count,
            )
        except Exception as exc:
            return self._fail_secure(str(exc))

    # ── Internal ─────────────────────────────────────────────────────────────

    def _evaluate_internal(
        self,
        payload:        str,
        ctx:            RequestContext,
        evidence:       RustEvidence,
        signal:         InjectionSignal,
        finding_count:  int,
        critical_count: int,
    ) -> GatewayVerdict:
        vid = str(uuid.uuid4())

        # ── Stage 1: Context Sanitization ────────────────────────────────────
        san_report = self._san.sanitize(ctx)
        if not san_report.is_safe():
            return self._build_verdict(
                vid, "BLOCK", "sanitizer",
                san_report, None, None,
                f"Contexto rejeitado pelo ContextSanitizer: {san_report.level.value}.",
            )

        # ── Stage 2: Payload Inspection ───────────────────────────────────────
        insp_report = self._insp.inspect(
            payload, signal, finding_count, critical_count,
        )
        if insp_report.action == InspectionAction.BLOCK:
            return self._build_verdict(
                vid, "BLOCK", "inspector",
                san_report, insp_report, None,
                f"Payload bloqueado pelo PayloadInspector: signal={signal.value}.",
            )

        # ── Stage 3: Ethical Context Engine ───────────────────────────────────
        ethical_verdict = self._engine.decide(
            evidence=evidence,
            context=san_report.sanitized,
        )

        final_action = ethical_verdict.final_action
        explain = self._aggregate_explain(san_report, insp_report, ethical_verdict, "")

        return self._build_verdict(
            vid, final_action, None,
            san_report, insp_report, ethical_verdict, explain,
        )

    def _build_verdict(
        self,
        vid:            str,
        action:         str,
        blocked_at:     Optional[str],
        san:            SanitizationReport,
        insp:           Optional[PayloadInspectionReport],
        ethical:        Optional[EthicalVerdict],
        explain_extra:  str = "",
    ) -> GatewayVerdict:
        now    = datetime.now(timezone.utc).isoformat()
        sig    = self._sign(action, vid, now)
        explain = self._aggregate_explain(san, insp, ethical, explain_extra)
        return GatewayVerdict(
            verdict_id=vid,
            action=action,
            explain_decision=explain,
            blocked_at=blocked_at,
            sanitization_level=san.level.value,
            inspection_action=insp.action.value if insp else "SKIPPED",
            ethical_action=ethical.final_action if ethical else None,
            decided_at_iso=now,
            signature=sig,
            contestable=True,
        )

    def _aggregate_explain(
        self,
        san:     SanitizationReport,
        insp:    Optional[PayloadInspectionReport],
        ethical: Optional[EthicalVerdict],
        extra:   str,
    ) -> str:
        parts = [
            "[GovernanceGateway] Pipeline completo.",
            f"  [1] Sanitizer : level={san.level.value}  changes={len(san.changes)}",
        ]
        if insp:
            parts.append(f"  [2] Inspector : action={insp.action.value}  signal={insp.injection_signal.value}")
        else:
            parts.append("  [2] Inspector : SKIPPED (contexto rejeitado antes)")
        if ethical:
            parts.append(
                f"  [3] Judiciario: original={ethical.original_action}"
                f"  final={ethical.final_action}"
                f"  mercy={ethical.mercy_applied}"
            )
        else:
            parts.append("  [3] Judiciario: SKIPPED")
        if extra:
            parts.append(f"  >> {extra}")
        parts.append("  Contestavel via /api/v1/contestation (SLA 24h — Rawls).")
        return "\n".join(parts)

    def _fail_secure(self, error: str) -> GatewayVerdict:
        now = datetime.now(timezone.utc).isoformat()
        vid = str(uuid.uuid4())
        sig = self._sign("BLOCK", vid, now)
        explain = (
            "[GovernanceGateway] FAIL-SECURE ativado.\n"
            f"  erro interno: {error}\n"
            "  Acao: BLOCK. Contestavel (SLA 24h — Rawls: erro do sistema nao e culpa do usuario)."
        )
        return GatewayVerdict(
            verdict_id=vid, action="BLOCK",
            explain_decision=explain,
            blocked_at="fail_secure",
            sanitization_level="UNKNOWN",
            inspection_action="UNKNOWN",
            ethical_action=None,
            decided_at_iso=now, signature=sig,
            contestable=True,
        )

    def _sign(self, action: str, vid: str, decided_at: str) -> str:
        payload = json.dumps(
            {"action": action, "decided_at": decided_at, "verdict_id": vid},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
