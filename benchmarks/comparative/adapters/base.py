"""
Abstract base class for guardrail system adapters.
Each adapter normalizes a vendor's API to a common interface
for fair comparison in the BuildToValue public benchmark.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class GuardrailResult:
    """Normalized result from any guardrail system."""
    action: str                       # Normalized: ALLOW | BLOCK | REDACT | EDUCATE | LOG
    detected: bool                    # Was a threat/PII detected?
    latency_ms: float                 # End-to-end call latency
    raw_response: dict = field(default_factory=dict)
    explainability: Optional[dict] = None   # Philosophical rationales (BTV-only)
    contestable: bool = False         # Supports appeals? (BTV-only)
    error: Optional[str] = None       # Error message if call failed


class GuardrailAdapter(ABC):
    """Base adapter interface for benchmarking."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the guardrail system."""
        ...

    @abstractmethod
    async def evaluate(self, input_text: str, context: dict) -> GuardrailResult:
        """
        Evaluate input text through the guardrail system.

        Args:
            input_text: The text to evaluate.
            context: Additional context (session_id, language, jurisdiction, etc.)

        Returns:
            GuardrailResult with normalized action, latency, and metadata.
        """
        ...

    def supports_category(self, category: str) -> bool:
        """Whether this adapter can handle the given test category."""
        return True

    def supports_language(self, lang: str) -> bool:
        """Whether this adapter supports the given language."""
        return lang == "en"

    def cost_per_request(self) -> Optional[float]:
        """Estimated cost per API call in USD, or None if self-hosted."""
        return None
