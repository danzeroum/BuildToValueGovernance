"""
ContextSanitizer - PROP-033 (Python Governance / Judiciario).
Sanitiza RequestContext antes do pipeline EthicalContextEngine.
Fundamentos: Jonas (responsabilidade preventiva), Rawls (equidade de entrada).
"""
from __future__ import annotations
import hashlib, hmac as _hmac, json, re, unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from .context_engine import RequestContext

_DOMAIN_ALLOWLIST  = frozenset({"development","testing","general","education",
                                 "healthcare","finance","legal","manufacturing","retail"})
_ROLE_ALLOWLIST    = frozenset({"anonymous","user","operator","admin","auditor","developer"})
_IP_RISK_ALLOWLIST = frozenset({"Low","Medium","High","Critical"})
_DRIFT_ALLOWLIST   = frozenset({"None","Low","Medium","High","Critical"})

_FIELD_MAX_LEN: dict[str, int] = {
    "agent_id": 128, "session_id": 256, "domain": 64,
    "user_role": 32, "ip_jurisdiction": 8, "ip_risk": 16, "drift_level": 16,
}

_INJECTION_CONFIRMED = re.compile(
    r"<\|system\||<\|user\||<\|assistant\|"
    r"|\[INST\]|\[/INST\]|</s>|<s>"
    r"|<system>|</system>|<instruction>|</instruction>",
    re.IGNORECASE,
)
_INJECTION_SUSPICIOUS = re.compile(
    r"ignore\s+(?:all\s+)?previous|disregard\s+all"
    r"|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:an?\s+)?\w+"
    r"|pretend\s+you\s+are|new\s+persona|override\s+(?:system|instructions?)",
    re.IGNORECASE,
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class SanitizationLevel(str, Enum):
    CLEAN      = "CLEAN"
    NORMALIZED = "NORMALIZED"
    CORRECTED  = "CORRECTED"
    SUSPICIOUS = "SUSPICIOUS"
    REJECTED   = "REJECTED"


@dataclass(frozen=True)
class SanitizationReport:
    """Resultado imutavel. explain_decision OBRIGATORIO. sanitized=None se REJECTED."""
    level:            SanitizationLevel
    explain_decision: str
    changes:          tuple
    sanitized:        Optional[RequestContext]
    decided_at_iso:   str
    signature:        str

    def is_safe(self) -> bool:
        return self.level != SanitizationLevel.REJECTED

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "explain_decision": self.explain_decision,
            "changes": list(self.changes),
            "is_safe": self.is_safe(),
            "decided_at_iso": self.decided_at_iso,
            "signature": self.signature,
        }


class ContextSanitizer:
    """Sanitiza RequestContext. Fail-secure: excecao -> REJECTED assinado."""

    def __init__(self, hmac_secret: bytes) -> None:
        if not hmac_secret:
            raise ValueError("hmac_secret nao pode ser vazio")
        self._secret = hmac_secret

    def sanitize(self, ctx: RequestContext) -> SanitizationReport:
        try:
            return self._sanitize_internal(ctx)
        except Exception as exc:
            return self._fail_secure(str(exc))

    def _sanitize_internal(self, ctx: RequestContext) -> SanitizationReport:
        changes: list[str] = []
        agent_id,        ch = _sanitize_string(ctx.agent_id,        "agent_id");        changes += ch
        session_id,      ch = _sanitize_string(ctx.session_id,      "session_id");      changes += ch
        domain,          ch = _sanitize_allowlist(ctx.domain,        "domain",        _DOMAIN_ALLOWLIST,  "general");   changes += ch
        user_role,       ch = _sanitize_allowlist(ctx.user_role,     "user_role",     _ROLE_ALLOWLIST,    "anonymous"); changes += ch
        ip_jurisdiction, ch = _sanitize_string(ctx.ip_jurisdiction,  "ip_jurisdiction");                               changes += ch
        ip_risk,         ch = _sanitize_allowlist(ctx.ip_risk,       "ip_risk",       _IP_RISK_ALLOWLIST, "Low");       changes += ch
        drift_level,     ch = _sanitize_allowlist(ctx.drift_level,   "drift_level",   _DRIFT_ALLOWLIST,   "None");      changes += ch

        level = _derive_level(changes)
        if level == SanitizationLevel.REJECTED:
            return self._reject("Injecao confirmada nos campos de contexto.", changes)

        sanitized = RequestContext(
            agent_id=agent_id, session_id=session_id, domain=domain,
            user_role=user_role, ip_jurisdiction=ip_jurisdiction,
            ip_risk=ip_risk, drift_level=drift_level,
            timestamp=ctx.timestamp,
            prior_sensitivity_tags=list(ctx.prior_sensitivity_tags),
            cumulative_risk=max(0.0, min(100.0, ctx.cumulative_risk)),
            active_combinations=list(ctx.active_combinations),
        )
        now = datetime.now(timezone.utc).isoformat()
        return SanitizationReport(
            level=level, explain_decision=_build_explain(level, changes),
            changes=tuple(changes), sanitized=sanitized,
            decided_at_iso=now, signature=self._sign(level, now, len(changes)),
        )

    def _reject(self, reason: str, changes: list) -> SanitizationReport:
        now = datetime.now(timezone.utc).isoformat()
        return SanitizationReport(
            level=SanitizationLevel.REJECTED,
            explain_decision=(
                "[ContextSanitizer] REJECTED - fail-secure.\n"
                f"  Razao: {reason}\n"
                "  Acao recomendada: BLOCK. (Jonas)."
            ),
            changes=tuple(changes), sanitized=None,
            decided_at_iso=now, signature=self._sign(SanitizationLevel.REJECTED, now, len(changes)),
        )

    def _fail_secure(self, error: str) -> SanitizationReport:
        now = datetime.now(timezone.utc).isoformat()
        return SanitizationReport(
            level=SanitizationLevel.REJECTED,
            explain_decision=(
                "[ContextSanitizer] FAIL-SECURE ativado.\n"
                f"  erro interno: {error}\n"
                "  Acao recomendada: BLOCK. (Jonas)."
            ),
            changes=(), sanitized=None,
            decided_at_iso=now, signature=self._sign(SanitizationLevel.REJECTED, now, 0),
        )

    def _sign(self, level: SanitizationLevel, decided_at: str, n_changes: int) -> str:
        payload = json.dumps(
            {"decided_at": decided_at, "level": level.value, "n_changes": n_changes},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()


def _strip_control(value: str) -> tuple:
    n = unicodedata.normalize("NFKC", value)
    c = _CONTROL_CHARS.sub("", n)
    return c, c != value

def _injection_level(value: str) -> SanitizationLevel:
    if _INJECTION_CONFIRMED.search(value):  return SanitizationLevel.REJECTED
    if _INJECTION_SUSPICIOUS.search(value): return SanitizationLevel.SUSPICIOUS
    return SanitizationLevel.CLEAN

def _sanitize_string(value: str, field: str) -> tuple:
    changes: list[str] = []
    max_len = _FIELD_MAX_LEN.get(field, 256)
    s, ctrl = _strip_control(value)
    if ctrl: changes.append(f"{field}: control_chars_removed")
    t = s.strip()
    if t != s: changes.append(f"{field}: whitespace_trimmed")
    s = t
    if len(s) > max_len:
        s = s[:max_len]; changes.append(f"{field}: truncated_to_{max_len}")
    inj = _injection_level(s)
    if inj == SanitizationLevel.REJECTED:
        changes.append(f"{field}: INJECTION_CONFIRMED_zeroed"); return "", changes
    if inj == SanitizationLevel.SUSPICIOUS:
        changes.append(f"{field}: INJECTION_SUSPICIOUS_zeroed"); return "", changes
    return s, changes

def _sanitize_allowlist(value: str, field: str, allowlist: frozenset, default: str) -> tuple:
    changes: list[str] = []
    c, ctrl = _strip_control(value)
    if ctrl: changes.append(f"{field}: control_chars_removed")
    n = c.strip()
    match = next((a for a in allowlist if a.lower() == n.lower()), None)
    if match is None:
        changes.append(f"{field}: unknown_value_replaced_with_{default!r}"); return default, changes
    if match != n: changes.append(f"{field}: normalized_to_{match!r}")
    return match, changes

def _derive_level(changes: list) -> SanitizationLevel:
    if any("INJECTION_CONFIRMED"  in c for c in changes): return SanitizationLevel.REJECTED
    if any("INJECTION_SUSPICIOUS" in c for c in changes): return SanitizationLevel.SUSPICIOUS
    if any("unknown_value_replaced" in c for c in changes): return SanitizationLevel.CORRECTED
    if changes: return SanitizationLevel.NORMALIZED
    return SanitizationLevel.CLEAN

def _build_explain(level: SanitizationLevel, changes: list) -> str:
    header = f"[ContextSanitizer] level={level.value}  changes={len(changes)}"
    if not changes: return header + "\n  Nenhuma alteracao necessaria."
    items  = "\n".join(f"  * {c}" for c in changes)
    footer = {
        SanitizationLevel.NORMALIZED: "Normalizacoes cosmeticas aplicadas.",
        SanitizationLevel.CORRECTED:  "Valores fora de allowlist substituidos por defaults seguros.",
        SanitizationLevel.SUSPICIOUS: "Padroes suspeitos detectados. Campos zeroed. (Jonas).",
        SanitizationLevel.REJECTED:   "Injecao confirmada. Contexto rejeitado. Recomendar BLOCK.",
    }.get(level, "")
    return f"{header}\n{items}\n  -> {footer}"
