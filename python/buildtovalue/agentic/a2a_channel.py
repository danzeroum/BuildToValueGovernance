"""
A2AChannel — Agent-to-Agent communication abstraction.

Provides a transport-agnostic interface for NegotiationEngine.
Implementations can be: in-process (testing), MCP (Arena).

ADR-054: Agentic Layer Architecture — Tier 2 (<500ms p99 for negotiation).

Invariants:
  - All implementations must be async (non-blocking)
  - receive() raises asyncio.TimeoutError on timeout (caller handles → ABORT)
  - MCPChannel is a Phase 1 roadmap stub — raises NotImplementedError
"""
from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

from .types import NegotiationMessage

import logging

logger = logging.getLogger("btv.agentic.a2a_channel")


# ─── Protocol (interface) ─────────────────────────────────────────────────────

@runtime_checkable
class A2AChannel(Protocol):
    """Abstract channel for agent-to-agent communication."""

    async def send(self, message: NegotiationMessage) -> None:
        """Send a NegotiationMessage to the remote agent."""
        ...

    async def receive(self, timeout: float) -> NegotiationMessage:
        """
        Receive next NegotiationMessage from remote agent.
        Raises asyncio.TimeoutError if no message arrives within timeout seconds.
        """
        ...


# ─── InProcessChannel ─────────────────────────────────────────────────────────

class InProcessChannel:
    """
    Two asyncio.Queue instances for bidirectional in-process communication.

    Used for unit tests and integration tests.
    Create a pair: (channel_a, channel_b) where channel_a.send → channel_b.receive.

    Usage:
        q_a_to_b: asyncio.Queue = asyncio.Queue()
        q_b_to_a: asyncio.Queue = asyncio.Queue()
        channel_a = InProcessChannel(outbox=q_a_to_b, inbox=q_b_to_a)
        channel_b = InProcessChannel(outbox=q_b_to_a, inbox=q_a_to_b)
    """

    def __init__(self,
                 outbox: asyncio.Queue[NegotiationMessage],
                 inbox: asyncio.Queue[NegotiationMessage]) -> None:
        self._outbox = outbox
        self._inbox = inbox

    async def send(self, message: NegotiationMessage) -> None:
        """Put message in outbox (immediately available to peer's inbox)."""
        await self._outbox.put(message)
        logger.debug("InProcessChannel.send round=%d type=%s", message.round_number, message.type)

    async def receive(self, timeout: float) -> NegotiationMessage:
        """
        Wait for message in inbox.
        Raises asyncio.TimeoutError if timeout exceeded.
        """
        try:
            msg = await asyncio.wait_for(self._inbox.get(), timeout=timeout)
            logger.debug("InProcessChannel.receive round=%d type=%s", msg.round_number, msg.type)
            return msg
        except asyncio.TimeoutError:
            logger.warning("InProcessChannel.receive timed out after %.1fs", timeout)
            raise


def make_in_process_pair() -> tuple[InProcessChannel, InProcessChannel]:
    """
    Factory: create a matched pair of InProcessChannels for testing.

    Returns:
        (channel_a, channel_b) — channel_a.send() → channel_b.receive()
                                  channel_b.send() → channel_a.receive()
    """
    q_a_to_b: asyncio.Queue[NegotiationMessage] = asyncio.Queue()
    q_b_to_a: asyncio.Queue[NegotiationMessage] = asyncio.Queue()
    channel_a = InProcessChannel(outbox=q_a_to_b, inbox=q_b_to_a)
    channel_b = InProcessChannel(outbox=q_b_to_a, inbox=q_a_to_b)
    return channel_a, channel_b


# ─── MCPChannel (Phase 1 roadmap stub) ────────────────────────────────────────

class MCPChannel:
    """
    Wraps existing BTV MCP server for A2A communication.

    Sends NegotiationMessages as MCP tool calls to a remote agent's BTV instance.
    Full implementation is Phase 1 roadmap (M3 Arena Integration Demo).

    This stub raises NotImplementedError to prevent accidental use in production.
    """

    def __init__(self, remote_mcp_url: str) -> None:
        self.remote_url = remote_mcp_url
        logger.warning(
            "MCPChannel is a Phase 1 roadmap stub. remote_url=%s — "
            "use InProcessChannel for testing.",
            remote_mcp_url,
        )

    async def send(self, message: NegotiationMessage) -> None:
        raise NotImplementedError(
            "MCPChannel.send() is Phase 1 roadmap. "
            "Use InProcessChannel for testing. "
            "See ADR-054 §Phase 1 for implementation plan."
        )

    async def receive(self, timeout: float) -> NegotiationMessage:
        raise NotImplementedError(
            "MCPChannel.receive() is Phase 1 roadmap. "
            "Use InProcessChannel for testing. "
            "See ADR-054 §Phase 1 for implementation plan."
        )
