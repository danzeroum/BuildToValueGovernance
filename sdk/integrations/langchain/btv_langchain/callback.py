"""
BTVGuardrailCallback — LangChain callback handler for BTV governance.

Hooks:
  on_llm_start  → validates prompt via btv.validate() or btv.decide()
  on_llm_end    → sanitizes LLM output via btv.sanitize()

Raises BTVBlockedByGuardrailError if the input action is in block_on.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional, Union

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from buildtovalue import AsyncBTVClient, BTVClient
from buildtovalue.models import VerdictAction


class BTVBlockedByGuardrailError(Exception):
    """Raised when the BTV guardrail blocks the prompt."""

    def __init__(self, verdict_id: str, action: str, rationale: str) -> None:
        self.verdict_id = verdict_id
        self.action = action
        self.rationale = rationale
        super().__init__(
            f"BTV guardrail blocked input. "
            f"verdict_id={verdict_id} action={action}: {rationale}"
        )


class BTVGuardrailCallback(BaseCallbackHandler):
    """
    LangChain callback that validates prompts and sanitizes outputs via BTV governance.

    Args:
        client: AsyncBTVClient or BTVClient instance.
        session_id: Optional session identifier for trust tracking.
        profile: Governance profile (general, healthcare, finance, legal).
        use_decide: If True, use /v1/decide (full ethical pipeline). Default: /v1/validate.
        block_on: Set of VerdictActions that trigger a block. Default: {BLOCK}.
        raise_on_block: If True, raise BTVBlockedByGuardrailError. Default: True.
        sanitize_output: If True, sanitize LLM output via btv.sanitize(). Default: True.
    """

    raise_error = False  # Override BaseCallbackHandler attribute

    def __init__(
        self,
        client: Union[AsyncBTVClient, BTVClient],
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
        use_decide: bool = False,
        block_on: frozenset = frozenset({"BLOCK"}),
        raise_on_block: bool = True,
        sanitize_output: bool = True,
    ) -> None:
        super().__init__()
        self._client = client
        self._session_id = session_id
        self._profile = profile
        self._use_decide = use_decide
        self._block_on = block_on
        self._raise_on_block = raise_on_block
        self._sanitize_output = sanitize_output
        self._is_async = isinstance(client, AsyncBTVClient)

    def _run_async(self, coro):
        """Run a coroutine from sync context."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result()
            else:
                return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def _validate_prompt(self, prompt: str) -> None:
        """Validate a single prompt string. Raises if blocked."""
        if self._is_async:
            if self._use_decide:
                verdict = self._run_async(
                    self._client.decide(prompt, session_id=self._session_id, profile=self._profile)
                )
            else:
                verdict = self._run_async(
                    self._client.validate(prompt, session_id=self._session_id, profile=self._profile)
                )
        else:
            if self._use_decide:
                verdict = self._client.decide(prompt, session_id=self._session_id, profile=self._profile)
            else:
                verdict = self._client.validate(prompt, session_id=self._session_id, profile=self._profile)

        action_str = verdict.action.value if hasattr(verdict.action, "value") else str(verdict.action)
        if action_str in self._block_on and self._raise_on_block:
            raise BTVBlockedByGuardrailError(
                verdict_id=verdict.verdict_id,
                action=action_str,
                rationale=getattr(verdict, "rationale", getattr(verdict, "message", "")),
            )

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Called before LLM receives prompts. Validates each prompt."""
        for prompt in prompts:
            if prompt.strip():
                self._validate_prompt(prompt)

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """Called after LLM returns. Sanitizes all output text."""
        if not self._sanitize_output:
            return

        for generation_list in response.generations:
            for generation in generation_list:
                text = getattr(generation, "text", "")
                if not text.strip():
                    continue

                if self._is_async:
                    result = self._run_async(self._client.sanitize(text))
                else:
                    result = self._client.sanitize(text)

                generation.text = result.sanitized
