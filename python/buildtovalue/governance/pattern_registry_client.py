"""
PatternRegistryClient v1.0.0 — Lê epoch atual do PatternRegistry (ADR-033/ADR-042).

Fontes em ordem de prioridade:
  1. Variável de ambiente BTV_PATTERN_EPOCH (CI/CD)
  2. Gateway /health/bias (runtime)
  3. Fallback conservador: epoch=0 (força re-execução)

≤ 200 linhas
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger("btv.governance.pattern_registry_client")

_DEFAULT_GATEWAY = "http://localhost:8080"
_TIMEOUT_SECONDS = 2.0


def get_current_epoch(gateway_url: Optional[str] = None) -> int:
    """
    Retorna epoch atual do PatternRegistry.

    Epoch binding (ADR-042): se epoch mudou desde último teste,
    os resultados em cache são invalidados automaticamente.

    Nunca levanta exceção — fallback para 0 garante re-execução segura.
    """
    # Prioridade 1: variável de ambiente (CI/CD — valor mais confiável)
    env_epoch = os.environ.get("BTV_PATTERN_EPOCH")
    if env_epoch is not None:
        try:
            epoch = int(env_epoch)
            logger.debug("epoch=%d (fonte: BTV_PATTERN_EPOCH)", epoch)
            return epoch
        except ValueError:
            logger.warning("BTV_PATTERN_EPOCH inválido: %r", env_epoch)

    # Prioridade 2: gateway /health/bias
    url = (gateway_url or os.environ.get("BTV_GATEWAY_URL", _DEFAULT_GATEWAY)).rstrip("/")
    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            resp = client.get(f"{url}/health/bias")
        if resp.status_code == 200:
            data  = resp.json()
            epoch = int(data.get("pattern_epoch", 0))
            logger.debug("epoch=%d (fonte: gateway %s)", epoch, url)
            return epoch
        logger.warning("gateway retornou HTTP %d para /health/bias", resp.status_code)
    except Exception as exc:
        logger.warning("falha ao consultar gateway para epoch: %s", exc)

    # Prioridade 3: fallback conservador
    logger.warning("epoch=0 (fallback) — forçando re-execução de testes")
    return 0


def epoch_changed(current_epoch: int, last_tested_epoch: int) -> bool:
    """Retorna True se epoch mudou e testes precisam re-executar."""
    return current_epoch != last_tested_epoch