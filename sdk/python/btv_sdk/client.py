"""
BTVClient — synchronous and asynchronous clients for the BTV governance gateway.

Quick start:
    from btv_sdk import BTVClient

    btv = BTVClient(api_key="...", gateway_url="http://localhost:8080")
    verdict = btv.decide("Meu CPF é 123.456.789-09", session_id="sess-001")

    if verdict.action == "BLOCK":
        appeal = btv.appeal(verdict.verdict_id, reason="CPF de teste ABNT",
                            grounds=["technical_error"])
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager, asynccontextmanager
from typing import Generator, AsyncGenerator, Optional

import httpx

from .exceptions import BTVAuthError, BTVBlockedError, BTVValidationError
from .models import (
    Appeal,
    AppealGrounds,
    SanitizeResult,
    TrustScore,
    ValidateVerdict,
    Verdict,
    VerdictAction,
)
from ._retry import retry_sync, retry_async

_DEFAULT_GATEWAY = "http://localhost:8080"
_DEFAULT_TIMEOUT = 30.0


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code == 401:
        raise BTVAuthError("Invalid or missing X-API-Key")
    if 400 <= resp.status_code < 500:
        detail = ""
        try:
            detail = resp.json().get("error", resp.text[:200])
        except Exception:
            detail = resp.text[:200]
        raise BTVValidationError(resp.status_code, detail)


# ─── Sync Client ─────────────────────────────────────────────────────────────


class BTVSession:
    """
    Context manager that scopes all calls to a fixed session_id.

        with btv.session("sess-001") as s:
            v1 = s.decide("Hello")
            v2 = s.decide("My SSN is ...")
    """

    def __init__(self, client: "BTVClient", session_id: str) -> None:
        self._client = client
        self.session_id = session_id

    def decide(self, input_text: str, profile: Optional[str] = None,
               agent_id: Optional[str] = None, **kwargs) -> Verdict:
        return self._client.decide(input_text, session_id=self.session_id,
                                   profile=profile, agent_id=agent_id, **kwargs)

    def validate(self, input_text: str, profile: Optional[str] = None, **kwargs) -> ValidateVerdict:
        return self._client.validate(input_text, session_id=self.session_id,
                                     profile=profile, **kwargs)

    def trust_score(self) -> TrustScore:
        return self._client.trust_score(self.session_id)

    def appeal(self, verdict_id: str, reason: str,
               grounds: Optional[list[str]] = None) -> Appeal:
        return self._client.appeal(verdict_id, reason, grounds)

    def __enter__(self) -> "BTVSession":
        return self

    def __exit__(self, *_) -> None:
        pass


class BTVClient:
    """
    Synchronous BTV governance client.

    Args:
        api_key: Your BTV API key (set BTV_API_KEYS on the gateway).
        gateway_url: Base URL of the BTV gateway (default: http://localhost:8080).
        timeout: Request timeout in seconds (default: 30).
        max_retries: Max retry attempts on transient errors (default: 3).
        raise_on_block: If True, raise BTVBlockedError when action==BLOCK (default: False).
    """

    def __init__(
        self,
        api_key: str,
        gateway_url: str = _DEFAULT_GATEWAY,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = 3,
        raise_on_block: bool = False,
    ) -> None:
        self._base_url = gateway_url.rstrip("/")
        self._headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        self._timeout = timeout
        self._max_retries = max_retries
        self._raise_on_block = raise_on_block
        self._http = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "BTVClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def session(self, session_id: Optional[str] = None) -> BTVSession:
        """Return a BTVSession that pins a session_id for all calls."""
        return BTVSession(self, session_id or str(uuid.uuid4()))

    def _post(self, path: str, body: dict) -> httpx.Response:
        url = f"{self._base_url}{path}"
        resp = retry_sync(
            lambda: self._http.post(url, json=body, headers=self._headers),
            max_retries=self._max_retries,
        )
        _raise_for_status(resp)
        return resp

    def _get(self, path: str) -> httpx.Response:
        url = f"{self._base_url}{path}"
        resp = retry_sync(
            lambda: self._http.get(url, headers=self._headers),
            max_retries=self._max_retries,
        )
        _raise_for_status(resp)
        return resp

    def decide(
        self,
        input_text: str,
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Verdict:
        """
        Run the full ethical governance pipeline (Rust + Python judiciary).

        Returns a Verdict with action, philosophical rationale, trust score, etc.
        If raise_on_block=True and action==BLOCK, raises BTVBlockedError.
        """
        body: dict = {"input": input_text}
        if session_id:
            body["session_id"] = session_id
        if profile:
            body["profile"] = profile
        if agent_id:
            body["agent_id"] = agent_id

        resp = self._post("/v1/decide", body)
        verdict = Verdict.model_validate(resp.json())

        if self._raise_on_block and verdict.action == VerdictAction.BLOCK:
            raise BTVBlockedError(verdict)

        return verdict

    def validate(
        self,
        input_text: str,
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> ValidateVerdict:
        """
        Run Rust-only scan (no ethical pipeline). Faster, less reasoning.
        Use decide() for full governance.
        """
        body: dict = {"input": input_text}
        if session_id:
            body["session_id"] = session_id
        if profile:
            body["profile"] = profile

        resp = self._post("/v1/validate", body)
        verdict = ValidateVerdict.model_validate(resp.json())

        if self._raise_on_block and verdict.action == VerdictAction.BLOCK:
            raise BTVBlockedError(verdict)

        return verdict

    def sanitize(self, text: str, session_id: Optional[str] = None) -> SanitizeResult:
        """Mask PII and neutralize injection patterns in text."""
        body: dict = {"text": text}
        if session_id:
            body["session_id"] = session_id

        resp = self._post("/v1/sanitize", body)
        return SanitizeResult.model_validate(resp.json())

    def appeal(
        self,
        verdict_id: str,
        reason: str,
        grounds: Optional[list[str]] = None,
        user_id: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> Appeal:
        """
        Submit an appeal against a verdict.

        Args:
            verdict_id: The VRD-... identifier from a prior decide/validate call.
            reason: Articulated reason (min 20 chars — Levinas principle).
            grounds: Philosophical grounds (see AppealGrounds enum).
            user_id: Opaque user identifier (defaults to "anonymous").
            evidence: Optional supporting evidence text.
        """
        body: dict = {
            "verdict_id": verdict_id,
            "user_id": user_id or "anonymous",
            "reason": reason,
            "grounds": grounds or ["false_positive"],
        }
        if evidence:
            body["evidence"] = evidence

        resp = self._post("/v1/appeals", body)
        return Appeal.model_validate(resp.json())

    def get_appeal(self, appeal_id: str) -> Appeal:
        """Get the current status of an appeal."""
        resp = self._get(f"/v1/appeals/{appeal_id}")
        return Appeal.model_validate(resp.json())

    def trust_score(self, session_id: str) -> TrustScore:
        """Get the multi-factorial trust score for a session."""
        resp = self._get(f"/v1/trust/{session_id}")
        return TrustScore.model_validate(resp.json())

    def health(self) -> dict:
        """Check gateway health (no auth required)."""
        resp = self._http.get(f"{self._base_url}/health", timeout=self._timeout)
        return resp.json()


# ─── Async Client ────────────────────────────────────────────────────────────


class AsyncBTVSession:
    """Async session context manager."""

    def __init__(self, client: "AsyncBTVClient", session_id: str) -> None:
        self._client = client
        self.session_id = session_id

    async def decide(self, input_text: str, profile: Optional[str] = None,
                     agent_id: Optional[str] = None) -> Verdict:
        return await self._client.decide(input_text, session_id=self.session_id,
                                         profile=profile, agent_id=agent_id)

    async def validate(self, input_text: str, profile: Optional[str] = None) -> ValidateVerdict:
        return await self._client.validate(input_text, session_id=self.session_id,
                                           profile=profile)

    async def trust_score(self) -> TrustScore:
        return await self._client.trust_score(self.session_id)

    async def appeal(self, verdict_id: str, reason: str,
                     grounds: Optional[list[str]] = None) -> Appeal:
        return await self._client.appeal(verdict_id, reason, grounds)

    async def __aenter__(self) -> "AsyncBTVSession":
        return self

    async def __aexit__(self, *_) -> None:
        pass


class AsyncBTVClient:
    """
    Async BTV governance client (asyncio/httpx).

    Usage:
        async with AsyncBTVClient(api_key="...") as btv:
            verdict = await btv.decide("Hello", session_id="sess-001")
    """

    def __init__(
        self,
        api_key: str,
        gateway_url: str = _DEFAULT_GATEWAY,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = 3,
        raise_on_block: bool = False,
    ) -> None:
        self._base_url = gateway_url.rstrip("/")
        self._headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        self._timeout = timeout
        self._max_retries = max_retries
        self._raise_on_block = raise_on_block
        self._http = httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncBTVClient":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    def session(self, session_id: Optional[str] = None) -> AsyncBTVSession:
        return AsyncBTVSession(self, session_id or str(uuid.uuid4()))

    async def _post(self, path: str, body: dict) -> httpx.Response:
        url = f"{self._base_url}{path}"
        resp = await retry_async(
            lambda: self._http.post(url, json=body, headers=self._headers),
            max_retries=self._max_retries,
        )
        _raise_for_status(resp)
        return resp

    async def _get(self, path: str) -> httpx.Response:
        url = f"{self._base_url}{path}"
        resp = await retry_async(
            lambda: self._http.get(url, headers=self._headers),
            max_retries=self._max_retries,
        )
        _raise_for_status(resp)
        return resp

    async def decide(
        self,
        input_text: str,
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Verdict:
        body: dict = {"input": input_text}
        if session_id:
            body["session_id"] = session_id
        if profile:
            body["profile"] = profile
        if agent_id:
            body["agent_id"] = agent_id

        resp = await self._post("/v1/decide", body)
        verdict = Verdict.model_validate(resp.json())

        if self._raise_on_block and verdict.action == VerdictAction.BLOCK:
            raise BTVBlockedError(verdict)

        return verdict

    async def validate(
        self,
        input_text: str,
        session_id: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> ValidateVerdict:
        body: dict = {"input": input_text}
        if session_id:
            body["session_id"] = session_id
        if profile:
            body["profile"] = profile

        resp = await self._post("/v1/validate", body)
        verdict = ValidateVerdict.model_validate(resp.json())

        if self._raise_on_block and verdict.action == VerdictAction.BLOCK:
            raise BTVBlockedError(verdict)

        return verdict

    async def sanitize(self, text: str, session_id: Optional[str] = None) -> SanitizeResult:
        body: dict = {"text": text}
        if session_id:
            body["session_id"] = session_id
        resp = await self._post("/v1/sanitize", body)
        return SanitizeResult.model_validate(resp.json())

    async def appeal(
        self,
        verdict_id: str,
        reason: str,
        grounds: Optional[list[str]] = None,
        user_id: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> Appeal:
        body: dict = {
            "verdict_id": verdict_id,
            "user_id": user_id or "anonymous",
            "reason": reason,
            "grounds": grounds or ["false_positive"],
        }
        if evidence:
            body["evidence"] = evidence

        resp = await self._post("/v1/appeals", body)
        return Appeal.model_validate(resp.json())

    async def get_appeal(self, appeal_id: str) -> Appeal:
        resp = await self._get(f"/v1/appeals/{appeal_id}")
        return Appeal.model_validate(resp.json())

    async def trust_score(self, session_id: str) -> TrustScore:
        resp = await self._get(f"/v1/trust/{session_id}")
        return TrustScore.model_validate(resp.json())

    async def health(self) -> dict:
        resp = await self._http.get(f"{self._base_url}/health", timeout=self._timeout)
        return resp.json()
