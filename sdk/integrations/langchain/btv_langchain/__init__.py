"""
BTV LangChain integration — guardrail callback for input/output governance.

Usage:
    from btv_sdk import AsyncBTVClient
    from btv_langchain import BTVGuardrailCallback

    btv = AsyncBTVClient(api_key="your-key")
    callback = BTVGuardrailCallback(client=btv, session_id="sess-001")

    llm = ChatOpenAI(callbacks=[callback])
    # Prompts are validated before being sent to the LLM.
    # Outputs are sanitized before being returned.
"""

from .callback import BTVBlockedByGuardrailError, BTVGuardrailCallback

__all__ = ["BTVGuardrailCallback", "BTVBlockedByGuardrailError"]
