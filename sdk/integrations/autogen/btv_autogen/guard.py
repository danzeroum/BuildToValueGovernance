"""
BTVAutoGenGuard — AutoGen message filter backed by BTV governance.

Compatible with pyautogen ConversableAgent.register_reply().
Validates incoming messages before the agent processes them.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional, Union

from btv_sdk import AsyncBTVClient, BTVClient


class BTVBlockedMessageError(Exception):
    """Raised when BTV governance blocks an AutoGen message."""

    def __init__(self, verdict_id: str, action: str, message: str = "") -> None:
        self.verdict_id = verdict_id
        self.action = action
        super().__init__(
            f"BTV governance blocked message. "
            f"verdict_id={verdict_id} action={action}: {message}"
        )


class BTVAutoGenGuard:
    """
    AutoGen message filter that validates messages via BTV governance.

    Compatible with ConversableAgent.register_reply() pattern.
    Returns (True, None) to allow the message, raises or returns blocked reply
    if governance action is in block_on.

    Args:
        client: BTVClient or AsyncBTVClient.
        session_id: Optional session identifier for trust tracking.
        profile: Governance profile (general, healthcare, finance, legal).
        use_decide: If True, use /v1/decide. Default: /v1/validate.
        block_on: Actions that trigger a block. Default: {"BLOCK"}.
        raise_on_block: Raise BTVBlockedMessageError on block. Default: False.
            When False, returns (True, blocked_reply_text) instead.
        blocked_reply: Reply text returned when message is blocked and
            raise_on_block=False.
    """

    def __init__(
        self,
        client: Union[BTVClient, AsyncBTVClient],
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
        use_decide: bool = False,
        block_on: frozenset = frozenset({"BLOCK"}),
        raise_on_block: bool = False,
        blocked_reply: str = "I cannot process this request due to governance policy.",
    ) -> None:
        self._client = client
        self._session_id = session_id
        self._profile = profile
        self._use_decide = use_decide
        self._block_on = block_on
        self._raise_on_block = raise_on_block
        self._blocked_reply = blocked_reply
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

    def _validate(self, text: str):
        if self._is_async:
            if self._use_decide:
                return self._run_async(
                    self._client.decide(text, session_id=self._session_id, profile=self._profile)
                )
            return self._run_async(
                self._client.validate(text, session_id=self._session_id, profile=self._profile)
            )
        else:
            if self._use_decide:
                return self._client.decide(text, session_id=self._session_id, profile=self._profile)
            return self._client.validate(text, session_id=self._session_id, profile=self._profile)

    def check_message(
        self,
        recipient: Any,
        messages: Optional[list[dict]] = None,
        sender: Any = None,
        config: Any = None,
    ) -> tuple[bool, Optional[str]]:
        """
        AutoGen reply function. Validates the last message content.

        Returns:
            (False, None) — pass-through (not handled, let next handler run)
            (True, blocked_reply) — message blocked, return blocked_reply
            Raises BTVBlockedMessageError if raise_on_block=True.

        Registration:
            agent.register_reply(
                trigger=autogen.ConversableAgent,
                reply_func=guard.check_message,
                position=0,
            )
        """
        if not messages:
            return False, None

        last_message = messages[-1]
        content = last_message.get("content", "")
        if not content or not content.strip():
            return False, None

        verdict = self._validate(content)
        action_str = verdict.action.value if hasattr(verdict.action, "value") else str(verdict.action)

        if action_str in self._block_on:
            if self._raise_on_block:
                raise BTVBlockedMessageError(
                    verdict_id=verdict.verdict_id,
                    action=action_str,
                    message=getattr(verdict, "message", getattr(verdict, "rationale", "")),
                )
            return True, self._blocked_reply

        return False, None
