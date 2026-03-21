"""
BTV AutoGen integration — message filter for AI agent governance.

Usage:
    from buildtovalue import BTVClient
    from btv_autogen import BTVAutoGenGuard

    btv = BTVClient(api_key="your-key")
    guard = BTVAutoGenGuard(client=btv, session_id="sess-001")

    # Register as a reply function:
    agent.register_reply(
        trigger=autogen.ConversableAgent,
        reply_func=guard.check_message,
        position=0,  # run first
    )
"""

from .guard import BTVAutoGenGuard, BTVBlockedMessageError

__all__ = ["BTVAutoGenGuard", "BTVBlockedMessageError"]
