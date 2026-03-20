"""
BuildToValue adapter — calls both /v1/validate (Rust-only) and /v1/decide (full pipeline).
"""

import os
import time
from typing import Optional

import httpx

from .base import GuardrailAdapter, GuardrailResult


class BTVAdapter(GuardrailAdapter):
    """Adapter for BuildToValue governance platform."""

    def __init__(
        self,
        gateway_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.gateway_url = gateway_url or os.environ.get("BTV_GATEWAY_URL", "http://localhost:8080")
        self.api_key = api_key or os.environ.get("BTV_API_KEY", "")
        self._client = httpx.AsyncClient(
            base_url=self.gateway_url,
            headers={"X-API-Key": self.api_key} if self.api_key else {},
            timeout=15.0,
        )

    @property
    def name(self) -> str:
        return "BuildToValue"

    async def evaluate(self, input_text: str, context: dict) -> GuardrailResult:
        """Evaluate using /v1/validate (Rust-only fast path)."""
        start = time.perf_counter()
        try:
            resp = await self._client.post("/v1/validate", json={
                "input": input_text,
                "session_id": context.get("session_id", "benchmark"),
            })
            latency_ms = (time.perf_counter() - start) * 1000
            data = resp.json()
            return GuardrailResult(
                action=data.get("action", "UNKNOWN"),
                detected=data.get("finding_count", 0) > 0,
                latency_ms=latency_ms,
                raw_response=data,
                contestable=data.get("contestable", False),
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                action="ERROR",
                detected=False,
                latency_ms=latency_ms,
                error=str(e),
            )

    async def evaluate_decide(self, input_text: str, context: dict) -> GuardrailResult:
        """Evaluate using /v1/decide (full philosophical pipeline)."""
        start = time.perf_counter()
        try:
            resp = await self._client.post("/v1/decide", json={
                "input_text": input_text,
                "session_id": context.get("session_id", "benchmark"),
                "profile": context.get("profile"),
            })
            latency_ms = (time.perf_counter() - start) * 1000
            data = resp.json()
            return GuardrailResult(
                action=data.get("action", "UNKNOWN"),
                detected=data.get("finding_count", 0) > 0 or data.get("action") != "ALLOW",
                latency_ms=latency_ms,
                raw_response=data,
                explainability={
                    "rationale": data.get("rationale"),
                    "mercy_applied": data.get("mercy_applied"),
                    "mercy_scenario": data.get("mercy_scenario"),
                    "trust_score": data.get("trust_score"),
                },
                contestable=data.get("contestable", False),
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                action="ERROR",
                detected=False,
                latency_ms=latency_ms,
                error=str(e),
            )

    def supports_language(self, lang: str) -> bool:
        return True  # BTV supports multilingual via kernel regex + SLM

    def cost_per_request(self) -> Optional[float]:
        return None  # Self-hosted

    async def close(self):
        await self._client.aclose()
