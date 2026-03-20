"""
NeMo Guardrails adapter for benchmark comparison.
Requires: pip install nemoguardrails
"""

import os
import time
from typing import Optional

import httpx

from .base import GuardrailAdapter, GuardrailResult


class NeMoGuardrailsAdapter(GuardrailAdapter):
    """Adapter for NVIDIA NeMo Guardrails."""

    def __init__(self, endpoint: Optional[str] = None):
        self.endpoint = endpoint or os.environ.get("NEMO_GUARDRAILS_URL", "http://localhost:8090")
        self._client = httpx.AsyncClient(base_url=self.endpoint, timeout=30.0)

    @property
    def name(self) -> str:
        return "NeMo Guardrails"

    async def evaluate(self, input_text: str, context: dict) -> GuardrailResult:
        start = time.perf_counter()
        try:
            resp = await self._client.post("/v1/chat/completions", json={
                "model": "guardrails",
                "messages": [{"role": "user", "content": input_text}],
            })
            latency_ms = (time.perf_counter() - start) * 1000
            data = resp.json()
            # NeMo returns a chat completion; blocked responses are indicated by
            # a refusal message or empty content
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            blocked = "cannot" in content.lower() or "sorry" in content.lower() or not content
            return GuardrailResult(
                action="BLOCK" if blocked else "ALLOW",
                detected=blocked,
                latency_ms=latency_ms,
                raw_response=data,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            return GuardrailResult(action="ERROR", detected=False, latency_ms=latency_ms, error=str(e))

    def supports_language(self, lang: str) -> bool:
        return lang == "en"

    def cost_per_request(self) -> Optional[float]:
        return None  # Self-hosted

    async def close(self):
        await self._client.aclose()
