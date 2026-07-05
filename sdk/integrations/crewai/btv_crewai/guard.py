"""
BTVCrewGuard — decorator/wrapper for CrewAI tasks with BTV governance.

Validates task inputs and sanitizes outputs via the BTV governance gateway.
Compatible with CrewAI's Task and Agent patterns.
"""
from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, Optional, Union

from btv_sdk import AsyncBTVClient, BTVClient


class BTVBlockedTaskError(Exception):
    """Raised when BTV governance blocks a CrewAI task."""

    def __init__(self, verdict_id: str, action: str, rationale: str = "") -> None:
        self.verdict_id = verdict_id
        self.action = action
        super().__init__(
            f"BTV governance blocked task. "
            f"verdict_id={verdict_id} action={action}: {rationale}"
        )


class BTVCrewGuard:
    """
    Guard for CrewAI tasks that validates inputs and sanitizes outputs.

    Args:
        client: BTVClient or AsyncBTVClient.
        session_id: Optional session identifier for trust tracking.
        profile: Governance profile (general, healthcare, finance, legal).
        use_decide: If True, use /v1/decide. Default: /v1/validate.
        block_on: Actions that trigger a block. Default: {"BLOCK"}.
        raise_on_block: Raise BTVBlockedTaskError on block. Default: True.
        sanitize_output: Sanitize task output via btv.sanitize(). Default: True.
    """

    def __init__(
        self,
        client: Union[BTVClient, AsyncBTVClient],
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
        use_decide: bool = False,
        block_on: frozenset = frozenset({"BLOCK"}),
        raise_on_block: bool = True,
        sanitize_output: bool = True,
    ) -> None:
        self._client = client
        self._session_id = session_id
        self._profile = profile
        self._use_decide = use_decide
        self._block_on = block_on
        self._raise_on_block = raise_on_block
        self._sanitize_output = sanitize_output
        self._is_async = isinstance(client, AsyncBTVClient)

    def _run_async(self, coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def _validate(self, text: str) -> None:
        if self._is_async:
            if self._use_decide:
                verdict = self._run_async(
                    self._client.decide(text, session_id=self._session_id, profile=self._profile)
                )
            else:
                verdict = self._run_async(
                    self._client.validate(text, session_id=self._session_id, profile=self._profile)
                )
        else:
            if self._use_decide:
                verdict = self._client.decide(text, session_id=self._session_id, profile=self._profile)
            else:
                verdict = self._client.validate(text, session_id=self._session_id, profile=self._profile)

        action_str = verdict.action.value if hasattr(verdict.action, "value") else str(verdict.action)
        if action_str in self._block_on and self._raise_on_block:
            raise BTVBlockedTaskError(
                verdict_id=verdict.verdict_id,
                action=action_str,
                rationale=getattr(verdict, "rationale", getattr(verdict, "message", "")),
            )

    def _sanitize(self, text: str) -> str:
        if not text or not text.strip():
            return text
        if self._is_async:
            result = self._run_async(self._client.sanitize(text))
        else:
            result = self._client.sanitize(text)
        return result.sanitized

    def protect(self, fn: Callable) -> Callable:
        """
        Decorator that wraps a task function with BTV governance.

        Validates the first string argument as input and sanitizes
        the string return value as output.

        Usage:
            @guard.protect
            def analyze_contract(text: str) -> str:
                return llm.run(text)
        """
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find first string argument to validate
            input_text = ""
            for arg in args:
                if isinstance(arg, str):
                    input_text = arg
                    break
            if not input_text:
                for val in kwargs.values():
                    if isinstance(val, str):
                        input_text = val
                        break

            if input_text:
                self._validate(input_text)

            result = fn(*args, **kwargs)

            if self._sanitize_output and isinstance(result, str):
                result = self._sanitize(result)

            return result

        return wrapper
