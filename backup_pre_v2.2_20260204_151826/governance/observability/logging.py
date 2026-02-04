
"""
Structured JSON logging for BuildToValue.

Logs are written in JSON format for easy parsing by Loki/ELK.
"""

import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict

# ═══════════════════════════════════════════════════════════════
# JSON Formatter
# ═══════════════════════════════════════════════════════════════

class JSONFormatter(logging.Formatter):
    """Format log records as JSON"""
    
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
        
        # Add trace context (if available)
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        
        if ctx.is_valid:
            log_data["trace_id"] = format(ctx.trace_id, '032x')
            log_data["span_id"] = format(ctx.span_id, '016x')
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add custom fields
        if hasattr(record, "verdict_id"):
            log_data["verdict_id"] = record.verdict_id
        
        if hasattr(record, "session_id"):
            log_data["session_id"] = record.session_id
        
        if hasattr(record, "action"):
            log_data["action"] = record.action
        
        return json.dumps(log_data)

# ═══════════════════════════════════════════════════════════════
# Logger Initialization
# ═══════════════════════════════════════════════════════════════

def init_logging(level: str = "INFO"):
    """Initialize structured logging"""
    
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
    logging.info("Structured logging initialized", extra={"log_format": "json"})

# ═══════════════════════════════════════════════════════════════
# Contextual Logging
# ═══════════════════════════════════════════════════════════════

class VerdictLogger:
    """Logger with verdict context"""
    
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
    
    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, **kwargs)

# ═══════════════════════════════════════════════════════════════
# Example Usage
# ═══════════════════════════════════════════════════════════════

"""
# Example log output (JSON):

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