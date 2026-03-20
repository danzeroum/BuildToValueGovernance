"""
Tests for retry logic — verifies exponential backoff and error propagation.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from buildtovalue._retry import retry_sync, retry_async
from buildtovalue.exceptions import BTVGatewayError, BTVRateLimitError


def _make_response(status: int, body: str = "", headers: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        content=body.encode(),
        headers=headers or {},
    )


class TestRetrySync:
    def test_returns_immediately_on_success(self):
        fn = MagicMock(return_value=_make_response(200, "ok"))
        result = retry_sync(fn, max_retries=3)
        assert result.status_code == 200
        fn.assert_called_once()

    def test_returns_on_non_retryable_4xx(self):
        fn = MagicMock(return_value=_make_response(422, "bad"))
        result = retry_sync(fn, max_retries=3)
        assert result.status_code == 422
        fn.assert_called_once()

    @patch("buildtovalue._retry.time.sleep")
    def test_retries_on_503(self, mock_sleep):
        responses = [
            _make_response(503),
            _make_response(503),
            _make_response(200, "ok"),
        ]
        fn = MagicMock(side_effect=responses)
        result = retry_sync(fn, max_retries=3, base_delay=1.0)
        assert result.status_code == 200
        assert fn.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("buildtovalue._retry.time.sleep")
    def test_raises_gateway_error_after_max_retries(self, mock_sleep):
        fn = MagicMock(return_value=_make_response(503))
        with pytest.raises(BTVGatewayError) as exc:
            retry_sync(fn, max_retries=2, base_delay=1.0)
        assert exc.value.status_code == 503
        assert fn.call_count == 3  # initial + 2 retries

    @patch("buildtovalue._retry.time.sleep")
    def test_raises_rate_limit_error_on_429(self, mock_sleep):
        fn = MagicMock(return_value=_make_response(429, "", {"Retry-After": "30"}))
        with pytest.raises(BTVRateLimitError) as exc:
            retry_sync(fn, max_retries=2, base_delay=1.0)
        assert exc.value.retry_after == 30

    @patch("buildtovalue._retry.time.sleep")
    def test_raises_gateway_error_on_network_failure(self, mock_sleep):
        fn = MagicMock(side_effect=httpx.ConnectError("Connection refused"))
        with pytest.raises(BTVGatewayError):
            retry_sync(fn, max_retries=2, base_delay=1.0)
        assert fn.call_count == 3

    @patch("buildtovalue._retry.time.sleep")
    def test_exponential_backoff_delays(self, mock_sleep):
        fn = MagicMock(side_effect=[
            _make_response(503),
            _make_response(503),
            _make_response(503),
        ])
        with pytest.raises(BTVGatewayError):
            retry_sync(fn, max_retries=2, base_delay=2.0)
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays[0] == 2.0   # base * 2^0
        assert delays[1] == 4.0   # base * 2^1


class TestRetryAsync:
    @patch("asyncio.sleep", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_returns_immediately_on_success(self, mock_sleep):
        async def fn():
            return _make_response(200)

        result = await retry_async(fn, max_retries=3)
        assert result.status_code == 200
        mock_sleep.assert_not_called()

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_retries_on_502(self, mock_sleep):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return _make_response(502)
            return _make_response(200)

        result = await retry_async(fn, max_retries=3, base_delay=1.0)
        assert result.status_code == 200
        assert call_count == 3

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_raises_rate_limit_on_429(self, mock_sleep):
        async def fn():
            return _make_response(429, "", {"Retry-After": "60"})

        with pytest.raises(BTVRateLimitError) as exc:
            await retry_async(fn, max_retries=1, base_delay=1.0)
        assert exc.value.retry_after == 60

    @patch("asyncio.sleep", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_raises_on_network_error(self, mock_sleep):
        async def fn():
            raise httpx.TimeoutException("Timeout")

        with pytest.raises(BTVGatewayError):
            await retry_async(fn, max_retries=2, base_delay=1.0)
