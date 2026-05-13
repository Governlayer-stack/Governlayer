"""OpenAI drop-in wrapper.

Customers swap::

    from openai import OpenAI

for::

    from governlayer.openai_wrapper import OpenAI

and every ``chat.completions.create`` call is automatically pushed through
``/v1/govern``. BLOCK -> raise GovernLayerBlocked. ESCALATE_HUMAN -> warn on
stderr. APPROVE -> return normally.
"""
from __future__ import annotations

import sys
from typing import Any, Optional

try:
    from openai import OpenAI as _OpenAIBase
except ImportError as exc:  # pragma: no cover - import-time guard
    raise ImportError(
        "governlayer.openai_wrapper requires the 'openai' package. "
        "Install it with: pip install openai>=1.0"
    ) from exc

from .client import GovernLayerBlocked, GovernLayerClient, GovernLayerError

_BLOCK_ACTIONS = {"BLOCK", "BLOCKED", "DENY"}
_ESCALATE_ACTIONS = {"ESCALATE_HUMAN", "ESCALATE", "REVIEW"}


def _extract_reasoning_trace(response: Any) -> str:
    """Best-effort extraction of the assistant message content from a chat.completions response."""
    try:
        choices = getattr(response, "choices", None) or response["choices"]
        first = choices[0]
        message = getattr(first, "message", None) or first["message"]
        content = getattr(message, "content", None)
        if content is None and isinstance(message, dict):
            content = message.get("content")
        return content or ""
    except (AttributeError, KeyError, IndexError, TypeError):
        return ""


class _GovernedChatCompletions:
    """Wraps ``client.chat.completions`` and intercepts ``.create``."""

    def __init__(self, inner: Any, parent: "OpenAI"):
        self._inner = inner
        self._parent = parent

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        response = self._inner.create(*args, **kwargs)
        reasoning_trace = _extract_reasoning_trace(response)
        self._parent._evaluate_governance(reasoning_trace, response, kwargs)
        return response


class _GovernedChat:
    def __init__(self, inner: Any, parent: "OpenAI"):
        self._inner = inner
        self.completions = _GovernedChatCompletions(inner.completions, parent)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class OpenAI(_OpenAIBase):
    """Drop-in replacement for ``openai.OpenAI`` that governs every chat completion.

    Extra constructor kwargs:
        governlayer_api_key: API key for GovernLayer. Falls back to GOVERNLAYER_API_KEY env var.
        system_name: Logical name of the agent/system being governed (required).
        use_case: Default use_case to report. Defaults to system_name if omitted.
        governlayer_base_url: Override base URL (default https://www.governlayer.ai).
        governlayer_client: Pre-built GovernLayerClient (advanced; bypasses other gl kwargs).
    """

    def __init__(
        self,
        *args: Any,
        governlayer_api_key: Optional[str] = None,
        system_name: Optional[str] = None,
        use_case: Optional[str] = None,
        governlayer_base_url: Optional[str] = None,
        governlayer_client: Optional[GovernLayerClient] = None,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)
        if not system_name:
            raise GovernLayerError(
                "OpenAI(governlayer) requires system_name=... so governance traces are attributable."
            )
        self._system_name = system_name
        self._use_case = use_case or system_name
        self._gl_client = governlayer_client or GovernLayerClient(
            api_key=governlayer_api_key,
            base_url=governlayer_base_url or "https://www.governlayer.ai",
        )
        # Replace the chat namespace with our governed proxy.
        self.chat = _GovernedChat(self.chat, self)

    def _evaluate_governance(self, reasoning_trace: str, llm_response: Any, kwargs: dict) -> None:
        if not reasoning_trace:
            # Nothing to govern (e.g. tool-only call). Skip silently.
            return
        result = self._gl_client.govern(
            system_name=self._system_name,
            use_case=self._use_case,
            reasoning_trace=reasoning_trace,
            model=kwargs.get("model"),
        )
        action = str(result.get("action", "")).upper()
        if action in _BLOCK_ACTIONS:
            raise GovernLayerBlocked(
                f"GovernLayer blocked response for system '{self._system_name}': "
                f"{result.get('reason', result)}",
                governance=result,
                llm_response=llm_response,
            )
        if action in _ESCALATE_ACTIONS:
            sys.stderr.write(
                f"[governlayer] ESCALATE_HUMAN for system '{self._system_name}': "
                f"{result.get('reason', 'human review required')}\n"
            )
