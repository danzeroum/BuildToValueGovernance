"""
Shared types for governance module.
Extracted to break circular imports.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import time


class ActionType(Enum):
    """Ações possíveis."""
    ALLOW = "ALLOW"
    LOG = "LOG"
    EDUCATE = "EDUCATE"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


@dataclass
class RequestMetadata:
    """Metadados de requisição."""
    agent_id: str = "unknown"
    session_id: str = "unknown"
    user_role: str = "anonymous"
    domain: str = "general"
    timestamp: int = field(default_factory=lambda: int(time.time()))
    is_first_offense: bool = True
    has_prior_violations: bool = False
    trust_score: float = 0.5
    educational_mode: bool = False
    operation_type: Optional[str] = None
    criticality: str = "MEDIUM"
    user_history: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EthicalContext:
    """Contexto ético derivado de RequestMetadata."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: int = field(default_factory=lambda: int(time.time()))
    user_history: Dict[str, Any] = field(default_factory=dict)
    trust_score: float = 0.5
    operation_type: Optional[str] = None
    criticality: str = "MEDIUM"
    is_first_offense: bool = True
    has_prior_violations: bool = False
    educational_mode: bool = False
    domain: str = "general"
    user_role: str = "anonymous"