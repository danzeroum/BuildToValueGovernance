"""contestability — subpacote do Contestability Loop (ADR-0095).

API pública reexportada aqui; ``contestability_loop.py`` é a facade de
compatibilidade retroativa.
"""
from ._loop import ContestabilityLoop
from ._types import (
    VALID_GROUNDS,
    VALID_MEDIATOR_RECOMMENDATIONS,
    Appeal,
    AppealStatus,
    EthicalVerdict,
    build_verdict,
)

__all__ = [
    "ContestabilityLoop",
    "Appeal",
    "AppealStatus",
    "EthicalVerdict",
    "build_verdict",
    "VALID_GROUNDS",
    "VALID_MEDIATOR_RECOMMENDATIONS",
]
