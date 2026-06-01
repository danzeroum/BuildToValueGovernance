"""RED tests — Passo 13: Observability — X-Request-ID, security counters, /metrics.

Verifiable without a real OTLP collector:
  1. Every response carries X-BTV-Request-ID (UUID).
  2. Client-supplied X-BTV-Request-ID is echoed back.
  3. GET /metrics → 200 with Content-Type text/plain (Prometheus format).
  4. /metrics body exposes btv_auth_failures_total.
  5. /metrics body exposes btv_rate_limit_exceeded_total.
  6. /metrics body exposes btv_http_request_duration_seconds.
  7. 401 response increments btv_auth_failures_total counter.
"""
import os
import re

import pytest
from fastapi.testclient import TestClient

from buildtovalue.api.app import app

pytestmark = pytest.mark.security

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app, follow_redirects=False) as c:
        yield c


@pytest.fixture(scope="module")
def client_auth():
    """Client with auth enabled so unauthenticated requests → 401."""
    os.environ["BTV_API_KEYS"] = "btv_obs_key"
    from buildtovalue.api.auth import init_auth

    init_auth()
    with TestClient(app, follow_redirects=False) as c:
        yield c
    os.environ.pop("BTV_API_KEYS", None)


class TestRequestIdMiddleware:
    """Every response must carry X-BTV-Request-ID."""

    def test_response_has_request_id_header(self, client):
        res = client.get("/health")
        assert "x-btv-request-id" in {k.lower() for k in res.headers}, (
            "every response must include X-BTV-Request-ID"
        )

    def test_generated_request_id_is_uuid4(self, client):
        res = client.get("/health")
        rid = res.headers.get("x-btv-request-id", "")
        assert _UUID4_RE.match(rid), f"X-BTV-Request-ID must be UUID4 (got {rid!r})"

    def test_client_supplied_request_id_is_echoed(self, client):
        custom_id = "my-custom-req-id-12345"
        res = client.get("/health", headers={"X-BTV-Request-ID": custom_id})
        echoed = res.headers.get("x-btv-request-id", "")
        assert echoed == custom_id, (
            f"client-supplied X-BTV-Request-ID must be echoed (got {echoed!r})"
        )


class TestPrometheusMetricsEndpoint:
    """GET /metrics must return raw Prometheus text format."""

    def test_metrics_endpoint_returns_200(self, client):
        res = client.get("/metrics")
        assert res.status_code == 200, f"/metrics must return 200 (got {res.status_code})"

    def test_metrics_content_type_is_prometheus_text(self, client):
        res = client.get("/metrics")
        ct = res.headers.get("content-type", "")
        assert "text/plain" in ct, (
            f"/metrics must return text/plain Prometheus format (got {ct!r})"
        )

    def test_metrics_body_contains_auth_failures_counter(self, client):
        res = client.get("/metrics")
        assert "btv_auth_failures_total" in res.text, (
            "/metrics must expose btv_auth_failures_total counter"
        )

    def test_metrics_body_contains_rate_limit_counter(self, client):
        res = client.get("/metrics")
        assert "btv_rate_limit_exceeded_total" in res.text, (
            "/metrics must expose btv_rate_limit_exceeded_total counter"
        )

    def test_metrics_body_contains_latency_histogram(self, client):
        res = client.get("/metrics")
        assert "btv_http_request_duration_seconds" in res.text, (
            "/metrics must expose btv_http_request_duration_seconds histogram"
        )


class TestSecurityCounters:
    """Security counters must increment on matching HTTP status codes."""

    def test_auth_failure_counter_increments_on_401(self, client_auth):
        from prometheus_client import REGISTRY

        before = REGISTRY.get_sample_value("btv_auth_failures_total") or 0.0

        # Unauthenticated request → 401
        client_auth.get("/v1/trust/sess-x")

        after = REGISTRY.get_sample_value("btv_auth_failures_total") or 0.0
        assert after == before + 1.0, (
            f"btv_auth_failures_total must increment on 401 "
            f"(was {before}, got {after})"
        )
