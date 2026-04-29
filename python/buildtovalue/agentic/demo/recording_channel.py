"""
RecordingChannel — InProcessChannel wrapper that emits a callback on every
send/receive, enabling the demo to capture every NegotiationMessage as a
narratable Step without modifying production code.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from buildtovalue.agentic.a2a_channel import InProcessChannel
from buildtovalue.agentic.types import NegotiationMessage


# Callback signature: (direction, peer_label, message) — sync or async-returning-None.
EventCallback = Callable[[str, str, NegotiationMessage], None]


class RecordingChannel(InProcessChannel):
    """
    Drop-in replacement for InProcessChannel that calls `on_event` on every
    send (direction="sent") and receive (direction="received").

    `peer_label` identifies which side of the channel this is — useful for the
    UI to attribute messages to AGENT_A vs AGENT_B vs RED_TEAM.
    """

    def __init__(
        self,
        outbox: asyncio.Queue[NegotiationMessage],
        inbox: asyncio.Queue[NegotiationMessage],
        on_event: EventCallback,
        peer_label: str,
    ) -> None:
        super().__init__(outbox=outbox, inbox=inbox)
        self._on_event = on_event
        self._peer = peer_label

    async def send(self, message: NegotiationMessage) -> None:
        self._on_event("sent", self._peer, message)
        await super().send(message)

    async def receive(self, timeout: float) -> NegotiationMessage:
        msg = await super().receive(timeout)
        self._on_event("received", self._peer, msg)
        return msg


def make_recording_pair(
    on_event: EventCallback,
    label_a: str = "AGENT_A",
    label_b: str = "AGENT_B",
) -> tuple[RecordingChannel, RecordingChannel]:
    """Factory mirroring `make_in_process_pair`, but with event capture."""
    q_a_to_b: asyncio.Queue[NegotiationMessage] = asyncio.Queue()
    q_b_to_a: asyncio.Queue[NegotiationMessage] = asyncio.Queue()
    chan_a = RecordingChannel(
        outbox=q_a_to_b, inbox=q_b_to_a, on_event=on_event, peer_label=label_a,
    )
    chan_b = RecordingChannel(
        outbox=q_b_to_a, inbox=q_a_to_b, on_event=on_event, peer_label=label_b,
    )
    return chan_a, chan_b
