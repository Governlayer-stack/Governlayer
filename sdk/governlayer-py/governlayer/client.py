"""GovernLayerClient — minimal synchronous client for the /v1/govern endpoint."""
from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from ._config import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    build_govern_url,
    resolve_api_key,
    resolve_base_url,
)


class GovernLayerError(Exception):
    """Raised on any non-2xx response from the GovernLayer API or transport failure."""

    def __init__(self, message: str, status_code: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class GovernLayerBlocked(GovernLayerError):
    """Raised when GovernLayer governance returns action == 'BLOCK'.

    The wrapped LLM response (if any) is attached as ``llm_response`` so the
    caller can still inspect/log what would have been returned.
    """

    def __init__(self, message: str, governance: Dict[str, Any], llm_response: Any = None):
        super().__init__(message)
        self.governance = governance
        self.llm_response = llm_response


class GovernLayerClient:
    """Minimal client for the GovernLayer governance API.

    Example::

        client = GovernLayerClient(api_key="gl_...")
        result = client.govern(
            system_name="fraud-detector",
            use_case="transaction_review",
            reasoning_trace="Flagged due to velocity anomaly...",
        )
        if result["action"] == "BLOCK":
            ...
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.api_key = resolve_api_key(api_key)
        self.base_url = resolve_base_url(base_url)
        self.timeout = timeout
        if not self.api_key:
            raise GovernLayerError(
                "Missing GovernLayer API key. Pass api_key=... or set GOVERNLAYER_API_KEY env var."
            )

    def _headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "governlayer-python/0.1.0",
        }

    def govern(
        self,
        system_name: str,
        use_case: str,
        reasoning_trace: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """POST to /v1/govern. Returns the parsed JSON response.

        Extra kwargs are merged into the request body, so callers can pass
        ``metadata``, ``model``, ``correlation_id``, etc. without an SDK bump.
        """
        url = build_govern_url(self.base_url)
        payload: Dict[str, Any] = {
            "system_name": system_name,
            "use_case": use_case,
            "reasoning_trace": reasoning_trace,
        }
        payload.update(kwargs)

        try:
            response = requests.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise GovernLayerError(f"GovernLayer transport error: {exc}") from exc

        if not (200 <= response.status_code < 300):
            body: Any
            try:
                body = response.json()
            except ValueError:
                body = response.text
            raise GovernLayerError(
                f"GovernLayer API returned {response.status_code}: {body}",
                status_code=response.status_code,
                body=body,
            )

        try:
            return response.json()
        except ValueError as exc:
            raise GovernLayerError(
                f"GovernLayer returned non-JSON body: {response.text!r}"
            ) from exc
