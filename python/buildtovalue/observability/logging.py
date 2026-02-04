"""
Structured JSON logging for BuildToValue.
Logs are written in JSON format for easy parsing by Loki/ELK.
Integrates with OpenTelemetry for trace correlation.
"""
import json
import logging
import sys
from datetime import datetime

# Import OpenTelemetry no topo (CORRIGIDO)
try:
    from opentelemetry import trace

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    print("Warning: OpenTelemetry not available. Trace correlation disabled.")


# ═══════════════════════════════════════════════════════════════
# JSON Formatter
# ═══════════════════════════════════════════════════════════════

class JSONFormatter(logging.Formatter):
    """
    Format log records as JSON.

    Output example:
    {
        "timestamp": "2026-02-04T16:18:23.456789Z",
        "level": "INFO",
        "logger": "governance.decision_engine",
        "message": "Ethical decision made",
        "trace_id": "0af7651916cd43dd8448eb211c80319c",
        "span_id": "b7ad6b7169203331",
        "verdict_id": "verd_9h0i1j2k3l4m5n6o",
        "action": "EDUCATE"
    }
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add trace context (if available) - CORRIGIDO: import no topo
        if OTEL_AVAILABLE:
            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx.is_valid:
                log_data["trace_id"] = format(ctx.trace_id, '032x')
                log_data["span_id"] = format(ctx.span_id, '016x')

        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add custom fields (passed via extra={})
        custom_fields = [
            "verdict_id", "session_id", "action", "profile",
            "trust_score", "mercy_score", "confidence"
        ]
        for field in custom_fields:
            if hasattr(record, field):
                log_data[field] = getattr(record, field)

        return json.dumps(log_data)


# ═══════════════════════════════════════════════════════════════
# Logger Initialization
# ═══════════════════════════════════════════════════════════════

def init_logging(level: str = "INFO"):
    """
    Initialize structured logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Usage:
        init_logging("INFO")
        logger = logging.getLogger(__name__)
        logger.info("Application started")
    """
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # JSON handler (stdout)
    json_handler = logging.StreamHandler(sys.stdout)
    json_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(json_handler)

    # Log initialization
    logging.info("Structured logging initialized", extra={
        "log_format": "json",
        "otel_available": OTEL_AVAILABLE
    })


# ═══════════════════════════════════════════════════════════════
# Contextual Logging
# ═══════════════════════════════════════════════════════════════

class VerdictLogger:
    """
    Logger with verdict context automatically injected.

    Usage:
        logger = VerdictLogger(
            verdict_id="verd_123",
            session_id="sess_456",
            action="EDUCATE"
        )
        logger.info("Decision made", confidence=0.87)
    """

    def __init__(self, verdict_id: str, session_id: str, action: str):
        self.logger = logging.getLogger(__name__)
        self.verdict_id = verdict_id
        self.session_id = session_id
        self.action = action

    def _log(self, level: int, message: str, **kwargs):
        extra = {
            "verdict_id": self.verdict_id,
            "session_id": self.session_id,
            "action": self.action,
            **kwargs,
        }
        self.logger.log(level, message, extra=extra)

    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, **kwargs)


# ═══════════════════════════════════════════════════════════════
# Structured Logging Helpers
# ═══════════════════════════════════════════════════════════════

def log_decision(
        logger: logging.Logger,
        verdict_id: str,
        session_id: str,
        action: str,
        confidence: float,
        trust_score: float,
        mercy_score: float,
        profile: str
):
    """
    Log ethical decision with structured context.

    Args:
        logger: Logger instance
        verdict_id: Verdict ID
        session_id: Session ID
        action: Action taken (ALLOW, BLOCK, etc.)
        confidence: Decision confidence
        trust_score: User trust score
        mercy_score: Mercy score applied
        profile: Profile name used
    """
    logger.info(
        "Ethical decision made",
        extra={
            "verdict_id": verdict_id,
            "session_id": session_id,
            "action": action,
            "confidence": confidence,
            "trust_score": trust_score,
            "mercy_score": mercy_score,
            "profile": profile,
            "mercy_applied": mercy_score > 0.5
        }
    )


def log_appeal_submitted(
        logger: logging.Logger,
        appeal_id: str,
        verdict_id: str,
        user_id: str,
        reason: str
):
    """
    Log appeal submission.

    Args:
        logger: Logger instance
        appeal_id: Appeal ID
        verdict_id: Original verdict being appealed
        user_id: User submitting appeal
        reason: Appeal reason
    """
    logger.info(
        "Appeal submitted",
        extra={
            "appeal_id": appeal_id,
            "verdict_id": verdict_id,
            "user_id": user_id,
            "reason_length": len(reason)
        }
    )


def log_appeal_resolved(
        logger: logging.Logger,
        appeal_id: str,
        outcome: str,
        resolution_time_seconds: float
):
    """
    Log appeal resolution.

    Args:
        logger: Logger instance
        appeal_id: Appeal ID
        outcome: "ACCEPTED" or "REJECTED"
        resolution_time_seconds: Time to resolve
    """
    logger.info(
        "Appeal resolved",
        extra={
            "appeal_id": appeal_id,
            "outcome": outcome,
            "resolution_time_seconds": resolution_time_seconds,
            "sla_compliant": resolution_time_seconds < 86400  # 24h SLA
        }
    )


# ═══════════════════════════════════════════════════════════════
# Example Usage
# ═══════════════════════════════════════════════════════════════

"""
Example usage:

    # Initialize logging
    init_logging("INFO")

    # Standard logger
    logger = logging.getLogger(__name__)
    logger.info("Application started")

    # Contextual logger
    verdict_logger = VerdictLogger(
        verdict_id="verd_9h0i1j2k3l4m5n6o",
        session_id="session_abc123",
        action="EDUCATE"
    )
    verdict_logger.info("Decision made", confidence=0.87, mercy_applied=True)

    # Structured helper
    log_decision(
        logger=logger,
        verdict_id="verd_123",
        session_id="sess_456",
        action="BLOCK",
        confidence=0.95,
        trust_score=0.45,
        mercy_score=0.3,
        profile="healthcare"
    )

Output (JSON):
{
  "timestamp": "2026-02-04T16:18:23.456789Z",
  "level": "INFO",
  "logger": "governance.decision_engine",
  "message": "Ethical decision made",
  "module": "decision_engine",
  "function": "decide",
  "line": 123,
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "span_id": "b7ad6b7169203331",
  "verdict_id": "verd_9h0i1j2k3l4m5n6o",
  "session_id": "session_abc123",
  "action": "EDUCATE",
  "confidence": 0.87,
  "mercy_applied": true
}
"""
