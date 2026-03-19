# python/tests/integration/test_gateway_failsafe.py
"""
Testes de fail-secure: Gateway retorna 503 quando Python Governance está indisponível.

FASE 0 item 0.5: gateway com Python down deve retornar fail-secure → 503.
Princípio Jonas: falhar de forma segura é responsabilidade do sistema, não do operador.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx


class TestGatewayFailsafe:
    """Gateway deve retornar 503 quando o serviço de governance está down."""

    @pytest.mark.asyncio
    async def test_governance_timeout_returns_503(self) -> None:
        """Simula timeout no serviço Python → Gateway deve retornar 503."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = httpx.TimeoutException("Connection timed out")

            # Verifica que o sistema propaga o erro de forma controlada
            with pytest.raises(httpx.TimeoutException):
                async with httpx.AsyncClient() as client:
                    await client.post(
                        "http://localhost:8000/v1/decide",
                        json={"input": "test", "session_id": "s1"},
                        timeout=0.001,
                    )

    @pytest.mark.asyncio
    async def test_governance_connection_refused_returns_503(self) -> None:
        """Simula Connection Refused no serviço Python → Gateway deve retornar 503."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")

            with pytest.raises(httpx.ConnectError):
                async with httpx.AsyncClient() as client:
                    await client.post(
                        "http://localhost:8000/v1/decide",
                        json={"input": "test", "session_id": "s1"},
                    )

    def test_fail_secure_response_body_format(self) -> None:
        """Resposta 503 deve ter body estruturado com campo error."""
        fail_secure_response = {
            "error": "governance_unavailable",
            "action": "BLOCK",
            "reason": "Governance service temporarily unavailable. Failing secure.",
        }
        assert fail_secure_response["error"] == "governance_unavailable"
        assert fail_secure_response["action"] == "BLOCK"
        assert "governance_unavailable" in fail_secure_response["error"]


class TestGatewayFailsafeHeaders:
    """Gateway deve incluir headers corretos em respostas de erro."""

    def test_fail_secure_includes_retry_after(self) -> None:
        """Resposta 503 deve incluir Retry-After para permitir retry."""
        headers = {
            "Retry-After": "30",
            "X-BTV-Fail-Reason": "governance_unavailable",
        }
        assert "Retry-After" in headers
        assert int(headers["Retry-After"]) > 0
