"""Async HTTP client for the GovernLayer API.

Centralises all API communication so callback, middleware, and decorators
share one well-tested transport layer.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .types import GovernanceResult, RiskProfile, ScanResult

logger = logging.getLogger("governlayer.client")

_DEFAULT_TIMEOUT = 30.0
_DEFAULT_API_URL = "https://web-production-bdd26.up.railway.app"


class GovernLayerClient:
    """Thin async wrapper around GovernLayer's REST API.

    Parameters
    ----------
    api_url:
        Base URL of the GovernLayer instance (no trailing slash).
    api_key:
        API key (``gl_xxx``) **or** JWT bearer token.
    timeout:
        HTTP request timeout in seconds.
    risk_profile:
        Default risk flags attached to every ``/v1/govern`` request.
        Can be overridden per-call.
    """

    def __init__(
        self,
        api_url: str = _DEFAULT_API_URL,
        api_key: str = "",
        timeout: float = _DEFAULT_TIMEOUT,
        risk_profile: RiskProfile | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.risk_profile = risk_profile or RiskProfile()
        self._client: httpx.AsyncClient | None = None

    # -- lifecycle --------------------------------------------------------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key.startswith("gl_"):
                headers["X-API-Key"] = self.api_key
            elif self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # -- API calls --------------------------------------------------------

    async def govern(
        self,
        system_name: str,
        reasoning_trace: str,
        use_case: str = "general",
        ai_decision: str = "",
        risk_profile: RiskProfile | None = None,
    ) -> GovernanceResult:
        """POST /v1/govern -- full governance pipeline."""
        profile = risk_profile or self.risk_profile
        payload: dict[str, Any] = {
            "system_name": system_name,
            "reasoning_trace": reasoning_trace,
            "use_case": use_case,
            "ai_decision": ai_decision,
            **profile.to_dict(),
        }
        client = await self._ensure_client()
        resp = await client.post("/v1/govern", json=payload)
        resp.raise_for_status()
        data = resp.json()
        logger.debug("govern response: %s", data)
        return GovernanceResult.from_api_response(data)

    async def scan(
        self,
        system_name: str,
        reasoning_trace: str,
        use_case: str = "general",
        risk_profile: RiskProfile | None = None,
    ) -> ScanResult:
        """POST /v1/scan -- deterministic quick scan (no LLM)."""
        profile = risk_profile or self.risk_profile
        payload: dict[str, Any] = {
            "system_name": system_name,
            "reasoning_trace": reasoning_trace,
            "use_case": use_case,
            **profile.to_dict(),
        }
        client = await self._ensure_client()
        resp = await client.post("/v1/scan", json=payload)
        resp.raise_for_status()
        data = resp.json()
        logger.debug("scan response: %s", data)
        return ScanResult.from_api_response(data)

    async def risk(
        self,
        system_name: str,
        risk_profile: RiskProfile | None = None,
    ) -> dict[str, Any]:
        """POST /v1/risk -- deterministic risk scoring."""
        profile = risk_profile or self.risk_profile
        payload: dict[str, Any] = {
            "system_name": system_name,
            **profile.to_dict(),
        }
        client = await self._ensure_client()
        resp = await client.post("/v1/risk", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def ledger(self, limit: int = 50) -> dict[str, Any]:
        """GET /ledger -- fetch the audit trail."""
        client = await self._ensure_client()
        resp = await client.get("/ledger", params={"limit": limit})
        resp.raise_for_status()
        return resp.json()
