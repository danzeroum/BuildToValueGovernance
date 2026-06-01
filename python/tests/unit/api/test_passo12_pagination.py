"""RED tests — Passo 12: Pagination + sorting on listing endpoints.

Canonical envelope: {data: [...], pagination: {page, limit, total, pages}}.

Appeals  (/v1/appeals):      ?page=&limit= (default 1/20) + ?sort_by=&order=
Ledger   (/v1/ledger/query): ?page=&limit= (rename page_size→limit) + same envelope
"""
import os
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from buildtovalue.api.app import app


def _make_token() -> str:
    secret = os.environ.get("BTV_JWT_SECRET", "ci-test-jwt-secret-32bytes-padding!!")
    now = int(time.time())
    return jwt.encode(
        {"sub": "tester", "role": "admin", "iat": now, "exp": now + 3600},
        secret,
        algorithm="HS256",
    )


@pytest.fixture
def client(tmp_path):
    os.environ.pop("BTV_API_KEYS", None)
    os.environ["BTV_ENV"] = "development"
    os.environ["BTV_APPEALS_DB"] = str(tmp_path / "appeals.db")

    import buildtovalue.api.app as app_module
    app_module._contestability_loop = None

    token = _make_token()
    with TestClient(app_module.app, headers={"Authorization": f"Bearer {token}"}) as c:
        yield c

    os.environ.pop("BTV_APPEALS_DB", None)
    app_module._contestability_loop = None


def _submit(client, n: int = 1, user_id: str = "u1") -> list[str]:
    ids = []
    for i in range(n):
        r = client.post(
            "/v1/appeals",
            json={
                "audit_trail_id": i + 1,
                "user_id": user_id,
                "reason": f"Reason for appeal number {i + 1}, enough chars.",
            },
        )
        assert r.status_code == 201, r.json()
        ids.append(r.json()["appeal_id"])
    return ids


# ─── Appeals: canonical envelope ───────────────────────────────────────────────

class TestAppealsCanonicalEnvelope:
    """GET /v1/appeals must return {data:[...], pagination:{page,limit,total,pages}}."""

    def test_empty_list_has_canonical_envelope(self, client):
        res = client.get("/v1/appeals")
        assert res.status_code == 200
        body = res.json()
        assert "data" in body, "response must have 'data' key"
        assert "pagination" in body, "response must have 'pagination' key"
        pg = body["pagination"]
        for field in ("page", "limit", "total", "pages"):
            assert field in pg, f"pagination must have '{field}'"
        assert pg["total"] == 0
        assert pg["page"] == 1

    def test_list_returns_data_not_appeals_key(self, client):
        _submit(client, 2)
        res = client.get("/v1/appeals")
        body = res.json()
        assert "data" in body, "key must be 'data', not 'appeals'"
        assert isinstance(body["data"], list)
        assert len(body["data"]) == 2

    def test_total_field_in_pagination(self, client):
        _submit(client, 3)
        res = client.get("/v1/appeals")
        assert res.json()["pagination"]["total"] == 3


# ─── Appeals: pagination ────────────────────────────────────────────────────────

class TestAppealsPagination:
    """?page=&limit= slices the result set correctly."""

    def test_default_limit_is_20(self, client):
        res = client.get("/v1/appeals")
        assert res.json()["pagination"]["limit"] == 20

    def test_page1_limit2_returns_two_items(self, client):
        _submit(client, 5)
        res = client.get("/v1/appeals?page=1&limit=2")
        body = res.json()
        assert len(body["data"]) == 2
        assert body["pagination"]["page"] == 1
        assert body["pagination"]["limit"] == 2
        assert body["pagination"]["total"] == 5
        assert body["pagination"]["pages"] == 3  # ceil(5/2)

    def test_page2_limit2_returns_next_slice(self, client):
        _submit(client, 5)
        r1 = client.get("/v1/appeals?page=1&limit=2")
        r2 = client.get("/v1/appeals?page=2&limit=2")
        ids_p1 = {a["appeal_id"] for a in r1.json()["data"]}
        ids_p2 = {a["appeal_id"] for a in r2.json()["data"]}
        assert ids_p1.isdisjoint(ids_p2), "pages must not overlap"
        assert len(ids_p2) == 2

    def test_last_page_partial(self, client):
        _submit(client, 5)
        res = client.get("/v1/appeals?page=3&limit=2")
        assert len(res.json()["data"]) == 1  # 5 items, 2/page → page 3 has 1

    def test_beyond_last_page_returns_empty_data(self, client):
        _submit(client, 3)
        res = client.get("/v1/appeals?page=99&limit=10")
        assert res.json()["data"] == []
        assert res.json()["pagination"]["total"] == 3


# ─── Appeals: sorting ──────────────────────────────────────────────────────────

class TestAppealsSorting:
    """?sort_by=timestamp&order=asc|desc."""

    def test_sort_by_timestamp_desc_returns_newest_first(self, client):
        _submit(client, 3)
        res = client.get("/v1/appeals?sort_by=timestamp&order=desc")
        timestamps = [a["timestamp"] for a in res.json()["data"]]
        assert timestamps == sorted(timestamps, reverse=True), (
            "sort_by=timestamp&order=desc must return newest first"
        )

    def test_sort_by_timestamp_asc_returns_oldest_first(self, client):
        _submit(client, 3)
        res = client.get("/v1/appeals?sort_by=timestamp&order=asc")
        timestamps = [a["timestamp"] for a in res.json()["data"]]
        assert timestamps == sorted(timestamps), (
            "sort_by=timestamp&order=asc must return oldest first"
        )


# ─── Ledger: canonical envelope ────────────────────────────────────────────────

class TestLedgerCanonicalEnvelope:
    """/v1/ledger/query must use 'data' + canonical pagination keys."""

    def test_ledger_query_uses_data_not_entries(self, client):
        res = client.get("/v1/ledger/query")
        body = res.json()
        assert "data" in body, "ledger response must use 'data', not 'entries'"
        assert "entries" not in body, "'entries' key must be replaced by 'data'"

    def test_ledger_pagination_uses_limit_not_page_size(self, client):
        res = client.get("/v1/ledger/query")
        pg = res.json()["pagination"]
        assert "limit" in pg, "pagination must use 'limit', not 'page_size'"
        assert "page_size" not in pg, "'page_size' must be replaced by 'limit'"

    def test_ledger_pagination_uses_total_not_total_matched(self, client):
        res = client.get("/v1/ledger/query")
        pg = res.json()["pagination"]
        assert "total" in pg, "pagination must use 'total', not 'total_matched'"
        assert "total_matched" not in pg

    def test_ledger_pagination_uses_pages_not_total_pages(self, client):
        res = client.get("/v1/ledger/query")
        pg = res.json()["pagination"]
        assert "pages" in pg, "pagination must use 'pages', not 'total_pages'"
        assert "total_pages" not in pg

    def test_ledger_accepts_limit_query_param(self, client):
        res = client.get("/v1/ledger/query?limit=20")
        assert res.status_code == 200
        assert res.json()["pagination"]["limit"] == 20
