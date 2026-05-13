"""Internal config helpers for the GovernLayer SDK.

Centralizes env-var lookup and default endpoint construction so the
client, wrappers, and decorators all share the same resolution rules.
"""
from __future__ import annotations

import os
from typing import Optional

ENV_API_KEY = "GOVERNLAYER_API_KEY"
ENV_BASE_URL = "GOVERNLAYER_BASE_URL"

DEFAULT_BASE_URL = "https://www.governlayer.ai"
DEFAULT_TIMEOUT_SECONDS = 15
GOVERN_PATH = "/v1/govern"


def resolve_api_key(passed: Optional[str]) -> Optional[str]:
    """Return the explicit API key if given, otherwise the env var."""
    if passed:
        return passed
    return os.environ.get(ENV_API_KEY)


def resolve_base_url(passed: Optional[str]) -> str:
    """Return the explicit base URL if given, otherwise env var, otherwise default."""
    if passed:
        return passed.rstrip("/")
    return os.environ.get(ENV_BASE_URL, DEFAULT_BASE_URL).rstrip("/")


def build_govern_url(base_url: str) -> str:
    """Join the base URL with the /v1/govern path."""
    return f"{base_url.rstrip('/')}{GOVERN_PATH}"
