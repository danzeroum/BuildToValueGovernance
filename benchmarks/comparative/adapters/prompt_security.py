"""
Prompt Security adapter for benchmark comparison.
Requires: PROMPT_SECURITY_API_KEY environment variable.
"""

import os
import time
from typing import Optional

import httpx

from .base import GuardrailAdapter, GuardrailResult


class PromptSecurityAdapter(GuardrailAdapter):
    """Adapter for Prompt Security API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("PROMPT_SECURITY_API_KEY", "")
        self._client = httpx.AsyncClient(
            base_url="https://api.prompt.security",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=15.0,
        )

    @property
    def name(self) -> str:
        return "Prompt Security"

    async def evaluate(self, input_text: str, context: dict) -> GuardrailResult:
        start = time.perf_counter()
        try:
            resp = await self._client.post("/v1/protect", json={
                "prompt": input_text,
                "metadata": context,
            })
            latency_ms = (time.perf_counter() - start) * 1000
            data = resp.json()
            blocked = data.get("action", "").upper() == "BLOCK" or data.get("blocked", False)
            return GuardrailResult(
                action="BLOCK" if blocked else "ALLOW",
                detected=blocked or data.get("detected", False),
                latency_ms=latency_ms,
                raw_response=data,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            return GuardrailResult(action="ERROR", detected=False, latency_ms=latency_ms, error=str(e))

    def supports_language(self, lang: str) -> bool:
        return True

    def cost_per_request(self) -> Optional[float]:
        return 0.002  # Approximate pricing

    async def close(self):
        await self._client.aclose()
