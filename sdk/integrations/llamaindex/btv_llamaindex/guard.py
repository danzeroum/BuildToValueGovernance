"""
BTVQueryEngineGuard — wraps a LlamaIndex QueryEngine with BTV governance.

Pre-validates queries before sending to the engine.
Post-sanitizes responses before returning to the caller.
"""
from __future__ import annotations

import asyncio
from typing import Optional, Union

from btv_sdk import AsyncBTVClient, BTVClient


class BTVBlockedQueryError(Exception):
    """Raised when BTV governance blocks a query."""

    def __init__(self, verdict_id: str, action: str, message: str = "") -> None:
        self.verdict_id = verdict_id
        self.action = action
        super().__init__(
            f"BTV governance blocked query. "
            f"verdict_id={verdict_id} action={action}: {message}"
        )


class BTVQueryEngineGuard:
    """
    Wraps a LlamaIndex QueryEngine to pre/post-validate all queries and responses.

    Args:
        engine: Any LlamaIndex query engine (BaseQueryEngine subclass).
        client: BTVClient or AsyncBTVClient.
        session_id: Optional session identifier for trust tracking.
        profile: Governance profile (general, healthcare, finance, legal).
        use_decide: If True, use /v1/decide. Default: /v1/validate.
        block_on: Actions that trigger a block. Default: {"BLOCK"}.
        raise_on_block: Raise BTVBlockedQueryError on block. Default: True.
        sanitize_response: Sanitize LLM response via btv.sanitize(). Default: True.
    """

    def __init__(
        self,
        engine,
        client: Union[BTVClient, AsyncBTVClient],
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
        use_decide: bool = False,
        block_on: frozenset = frozenset({"BLOCK"}),
        raise_on_block: bool = True,
        sanitize_response: bool = True,
    ) -> None:
        self._engine = engine
        self._client = client
        self._session_id = session_id
        self._profile = profile
        self._use_decide = use_decide
        self._block_on = block_on
        self._raise_on_block = raise_on_block
        self._sanitize_response = sanitize_response
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

    def _check_verdict(self, verdict) -> None:
        action_str = verdict.action.value if hasattr(verdict.action, "value") else str(verdict.action)
        if action_str in self._block_on and self._raise_on_block:
            raise BTVBlockedQueryError(
                verdict_id=verdict.verdict_id,
                action=action_str,
                message=getattr(verdict, "message", getattr(verdict, "rationale", "")),
            )

    def _validate_sync(self, text: str) -> None:
        if self._use_decide:
            verdict = self._client.decide(text, session_id=self._session_id, profile=self._profile)
        else:
            verdict = self._client.validate(text, session_id=self._session_id, profile=self._profile)
        self._check_verdict(verdict)

    async def _validate_async(self, text: str) -> None:
        if self._use_decide:
            verdict = await self._client.decide(text, session_id=self._session_id, profile=self._profile)
        else:
            verdict = await self._client.validate(text, session_id=self._session_id, profile=self._profile)
        self._check_verdict(verdict)

    def query(self, query_str: str):
        """Validate query, call engine, sanitize response."""
        if self._is_async:
            self._run_async(self._validate_async(query_str))
        else:
            self._validate_sync(query_str)

        response = self._engine.query(query_str)

        if self._sanitize_response and response and hasattr(response, "response"):
            text = response.response or ""
            if text.strip():
                if self._is_async:
                    result = self._run_async(self._client.sanitize(text))
                else:
                    result = self._client.sanitize(text)
                response.response = result.sanitized

        return response

    async def aquery(self, query_str: str):
        """Async version of query()."""
        await self._validate_async(query_str)

        response = await self._engine.aquery(query_str)

        if self._sanitize_response and response and hasattr(response, "response"):
            text = response.response or ""
            if text.strip():
                result = await self._client.sanitize(text)
                response.response = result.sanitized

        return response
