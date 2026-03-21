"""
BTV LlamaIndex integration — query engine guard for input/output governance.

Usage:
    from buildtovalue import BTVClient
    from btv_llamaindex import BTVQueryEngineGuard

    btv = BTVClient(api_key="your-key")
    guard = BTVQueryEngineGuard(engine=your_engine, client=btv, session_id="sess-001")

    response = guard.query("What is the patient's diagnosis?")
"""

from .guard import BTVBlockedQueryError, BTVQueryEngineGuard

__all__ = ["BTVQueryEngineGuard", "BTVBlockedQueryError"]
