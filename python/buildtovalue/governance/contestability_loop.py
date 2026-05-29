"""Facade de compatibilidade retroativa (ADR-0095).

NÃO adicionar lógica aqui — toda a implementação vive em ``contestability/``
(``_types.py``, ``_loop.py``). Este módulo apenas reexporta a API pública para
que nenhum import existente quebre. ``contestability_escalation.py`` permanece
como módulo irmão (importa daqui), não migrado.
"""
from buildtovalue.governance.contestability import (  # noqa: F401
    VALID_GROUNDS,
    VALID_MEDIATOR_RECOMMENDATIONS,
    Appeal,
    AppealStatus,
    ContestabilityLoop,
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
