"""
BTV CrewAI integration — task guard for AI agent governance.

Usage:
    from buildtovalue import BTVClient
    from btv_crewai import BTVCrewGuard

    btv = BTVClient(api_key="your-key")
    guard = BTVCrewGuard(client=btv, profile="finance")

    @guard.protect
    def my_task(context: str) -> str:
        return agent.run(context)
"""

from .guard import BTVBlockedTaskError, BTVCrewGuard

__all__ = ["BTVCrewGuard", "BTVBlockedTaskError"]
