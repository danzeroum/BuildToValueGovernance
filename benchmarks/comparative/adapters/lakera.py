"""
Lakera Guard adapter for benchmark comparison.
Requires: LAKERA_API_KEY environment variable.
"""

import os
import time
from typing import Optional

import httpx

from .base import GuardrailAdapter, GuardrailResult


class LakeraGuardAdapter(GuardrailAdapter):
    """Adapter for Lakera Guard API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("LAKERA_API_KEY", "")
        self._client = httpx.AsyncClient(
            base_url="https://api.lakera.ai",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=15.0,
        )

    @property
    def name(self) -> str:
        return "Lakera Guard"

    async def evaluate(self, input_text: str, context: dict) -> GuardrailResult:
        start = time.perf_counter()
        try:
            resp = await self._client.post("/v1/guard", json={"input": input_text})
            latency_ms = (time.perf_counter() - start) * 1000
            data = resp.json()
            flagged = data.get("results", [{}])[0].get("flagged", False)
            categories = data.get("results", [{}])[0].get("categories", {})
            return GuardrailResult(
                action="BLOCK" if flagged else "ALLOW",
                detected=flagged,
                latency_ms=latency_ms,
                raw_response=data,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            return GuardrailResult(action="ERROR", detected=False, latency_ms=latency_ms, error=str(e))

    def supports_language(self, lang: str) -> bool:
        return True  # Lakera supports multilingual

    def cost_per_request(self) -> Optional[float]:
        return 0.001  # Approximate Lakera pricing

    async def close(self):
        await self._client.aclose()
