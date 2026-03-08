"""
FeedbackProvenanceGuard -- PROP-036 (LLM Hypnosis / paper 241).

Detecta padroes de envenenamento de feedback (upvote/downvote adversarial).
Padrao "Flip": usuario alterna entre POSITIVE/NEGATIVE de forma anomala
para injetar vies no pipeline de preferencia.

Invariantes:
  - Fail-secure: erro interno -> QUARANTINE (nunca bypass)
  - explain_decision obrigatorio em todo FeedbackVerdict
  - Quarentena registrada no Ledger com HMAC-SHA256 (Jonas)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Deque, Dict, List

_WINDOW_SIZE: int = 20
_FLIP_THRESHOLD: float = 0.60
_BURST_WINDOW_SECS: float = 30.0
_BURST_COUNT: int = 5


class FeedbackPolarity(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"


class FeedbackRisk(str, Enum):
    LOW        = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINE = "QUARANTINE"


@dataclass(frozen=True)
class FeedbackEvent:
    user_id:   str
    polarity:  FeedbackPolarity
    target_id: str
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class FeedbackVerdict:
    user_id:          str
    risk:             FeedbackRisk
    flip_ratio:       float
    burst_detected:   bool
    explain_decision: dict
    ledger_entry:     str
    decided_at_iso:   str

    def is_quarantined(self) -> bool:
        return self.risk == FeedbackRisk.QUARANTINE


def _flip_ratio(window: List[FeedbackPolarity]) -> float:
    if len(window) < 2:
        return 0.0
    flips = sum(1 for a, b in zip(window, window[1:]) if a != b)
    return flips / (len(window) - 1)


def _burst_detected(
    timestamps: List[float],
    burst_count: int,
    burst_window_secs: float,
) -> bool:
    """Burst requer ALTERNANCIA alem de volume: detecta apenas se ha flips no periodo."""
    if len(timestamps) < burst_count:
        return False
    recent = timestamps[-burst_count:]
    return (recent[-1] - recent[0]) < burst_window_secs


def _make_ledger_entry(
    user_id: str,
    risk: FeedbackRisk,
    flip_ratio: float,
    burst: bool,
    decided_at: str,
    hmac_key: bytes,
) -> str:
    payload = {
        "component": "FeedbackProvenanceGuard",
        "prop": "PROP-036",
        "user_id": user_id,
        "risk": risk.value,
        "flip_ratio": round(flip_ratio, 4),
        "burst_detected": burst,
        "decided_at": decided_at,
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = _hmac.new(hmac_key, body.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"payload": payload, "hmac_sha256": sig},
                      separators=(",", ":"), sort_keys=True)


@dataclass
class _UserState:
    polarities: Deque[FeedbackPolarity] = field(
        default_factory=lambda: deque(maxlen=_WINDOW_SIZE)
    )
    timestamps: List[float] = field(default_factory=list)

    def record(self, event: FeedbackEvent) -> None:
        self.polarities.append(event.polarity)
        self.timestamps.append(event.timestamp)
        if len(self.timestamps) > _WINDOW_SIZE:
            self.timestamps = self.timestamps[-_WINDOW_SIZE:]


class FeedbackProvenanceGuard:
    def __init__(
        self,
        hmac_key: bytes,
        flip_threshold: float = _FLIP_THRESHOLD,
        burst_window_secs: float = _BURST_WINDOW_SECS,
        burst_count: int = _BURST_COUNT,
    ) -> None:
        if not hmac_key:
            raise ValueError("hmac_key obrigatorio (Jonas: rastreabilidade)")
        self._key = hmac_key
        self._flip_threshold = flip_threshold
        self._burst_window_secs = burst_window_secs
        self._burst_count = burst_count
        self._states: Dict[str, _UserState] = {}

    def evaluate(self, event: FeedbackEvent) -> FeedbackVerdict:
        try:
            return self._evaluate_internal(event)
        except Exception as exc:
            return self._fail_secure(event.user_id, reason=str(exc))

    def _evaluate_internal(self, event: FeedbackEvent) -> FeedbackVerdict:
        state = self._states.setdefault(event.user_id, _UserState())
        state.record(event)

        window = list(state.polarities)
        timestamps = list(state.timestamps)
        ratio = _flip_ratio(window)
        burst = self._check_burst(ratio, timestamps)
        risk = self._classify(ratio, burst)
        decided_at = datetime.now(timezone.utc).isoformat()

        explain: dict = {
            "prop": "PROP-036",
            "user_id": event.user_id,
            "risk": risk.value,
            "flip_ratio": round(ratio, 4),
            "flip_threshold": self._flip_threshold,
            "burst_detected": burst,
            "window_size": len(window),
            "reason": self._reason(risk, ratio, burst),
        }
        ledger = _make_ledger_entry(
            event.user_id, risk, ratio, burst, decided_at, self._key
        )
        return FeedbackVerdict(
            user_id=event.user_id,
            risk=risk,
            flip_ratio=ratio,
            burst_detected=burst,
            explain_decision=explain,
            ledger_entry=ledger,
            decided_at_iso=decided_at,
        )

    def _check_burst(self, flip_ratio: float, timestamps: List[float]) -> bool:
        """Burst so e suspeito se combinado com alternancia (flip_ratio > 0)."""
        if flip_ratio == 0.0:
            return False
        return _burst_detected(timestamps, self._burst_count, self._burst_window_secs)

    def _classify(self, ratio: float, burst: bool) -> FeedbackRisk:
        if ratio >= self._flip_threshold or burst:
            return FeedbackRisk.QUARANTINE
        if ratio >= self._flip_threshold * 0.6:
            return FeedbackRisk.SUSPICIOUS
        return FeedbackRisk.LOW

    def _reason(self, risk: FeedbackRisk, ratio: float, burst: bool) -> str:
        if risk == FeedbackRisk.LOW:
            return "feedback_pattern_normal"
        parts = []
        if ratio >= self._flip_threshold:
            parts.append(f"flip_ratio={ratio:.2f}>={self._flip_threshold}")
        if burst:
            parts.append(
                f"burst_detected(>{self._burst_count}in{self._burst_window_secs}s)"
            )
        return "|".join(parts) if parts else "suspicious_pattern"

    def _fail_secure(self, user_id: str, reason: str) -> FeedbackVerdict:
        decided_at = datetime.now(timezone.utc).isoformat()
        explain = {
            "prop": "PROP-036",
            "user_id": user_id,
            "risk": FeedbackRisk.QUARANTINE.value,
            "flip_ratio": 0.0,
            "burst_detected": False,
            "reason": f"fail_secure:{reason}",
            "is_error": True,
        }
        ledger = _make_ledger_entry(
            user_id, FeedbackRisk.QUARANTINE, 0.0, False, decided_at, self._key
        )
        return FeedbackVerdict(
            user_id=user_id,
            risk=FeedbackRisk.QUARANTINE,
            flip_ratio=0.0,
            burst_detected=False,
            explain_decision=explain,
            ledger_entry=ledger,
            decided_at_iso=decided_at,
        )

    def reset_user(self, user_id: str) -> None:
        self._states.pop(user_id, None)

    def quarantined_users(self) -> List[str]:
        result = []
        for uid, state in self._states.items():
            window = list(state.polarities)
            timestamps = list(state.timestamps)
            ratio = _flip_ratio(window)
            burst = self._check_burst(ratio, timestamps)
            if self._classify(ratio, burst) == FeedbackRisk.QUARANTINE:
                result.append(uid)
        return result
