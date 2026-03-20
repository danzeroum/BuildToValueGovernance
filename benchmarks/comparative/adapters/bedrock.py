"""
AWS Bedrock Guardrails adapter for benchmark comparison.
Requires: AWS credentials and BEDROCK_GUARDRAIL_ID environment variable.
"""

import os
import time
from typing import Optional

from .base import GuardrailAdapter, GuardrailResult


class BedrockGuardrailsAdapter(GuardrailAdapter):
    """Adapter for AWS Bedrock Guardrails."""

    def __init__(self, guardrail_id: Optional[str] = None, region: Optional[str] = None):
        self.guardrail_id = guardrail_id or os.environ.get("BEDROCK_GUARDRAIL_ID", "")
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("bedrock-runtime", region_name=self.region)
        return self._client

    @property
    def name(self) -> str:
        return "AWS Bedrock Guardrails"

    async def evaluate(self, input_text: str, context: dict) -> GuardrailResult:
        start = time.perf_counter()
        try:
            client = self._get_client()
            resp = client.apply_guardrail(
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion="DRAFT",
                source="INPUT",
                content=[{"text": {"text": input_text}}],
            )
            latency_ms = (time.perf_counter() - start) * 1000
            action_str = resp.get("action", "NONE")
            blocked = action_str == "GUARDRAIL_INTERVENED"
            return GuardrailResult(
                action="BLOCK" if blocked else "ALLOW",
                detected=blocked,
                latency_ms=latency_ms,
                raw_response=resp,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            return GuardrailResult(action="ERROR", detected=False, latency_ms=latency_ms, error=str(e))

    def supports_language(self, lang: str) -> bool:
        return lang == "en"  # Bedrock guardrails primarily English

    def cost_per_request(self) -> Optional[float]:
        return 0.00075  # Approximate Bedrock pricing

    async def close(self):
        pass
