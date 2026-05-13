"""Anthropic drop-in wrapper.

Customers swap::

    from anthropic import Anthropic

for::

    from governlayer.anthropic_wrapper import Anthropic

and every ``messages.create`` is pushed through ``/v1/govern``.
"""
from __future__ import annotations

import sys
from typing import Any, Optional

try:
    from anthropic import Anthropic as _AnthropicBase
except ImportError as exc:  # pragma: no cover - import-time guard
    raise ImportError(
        "governlayer.anthropic_wrapper requires the 'anthropic' package. "
        "Install it with: pip install anthropic>=0.18"
    ) from exc

from .client import GovernLayerBlocked, GovernLayerClient, GovernLayerError

_BLOCK_ACTIONS = {"BLOCK", "BLOCKED", "DENY"}
_ESCALATE_ACTIONS = {"ESCALATE_HUMAN", "ESCALATE", "REVIEW"}


def _extract_reasoning_trace(response: Any) -> str:
    """Pull the first text block out of an anthropic messages.create response."""
    try:
        content = getattr(response, "content", None)
        if content is None and isinstance(response, dict):
            content = response.get("content")
        if not content:
            return ""
        parts = []
        for block in content:
            text = getattr(block, "text", None)
            if text is None and isinstance(block, dict):
                text = block.get("text")
            if text:
                parts.append(text)
        return "\n".join(parts)
    except (AttributeError, TypeError):
        return ""


class _GovernedMessages:
    def __init__(self, inner: Any, parent: "Anthropic"):
        self._inner = inner
        self._parent = parent

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        response = self._inner.create(*args, **kwargs)
        reasoning_trace = _extract_reasoning_trace(response)
        self._parent._evaluate_governance(reasoning_trace, response, kwargs)
        return response


class Anthropic(_AnthropicBase):
    """Drop-in replacement for ``anthropic.Anthropic`` that governs every messages.create call."""

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
                "Anthropic(governlayer) requires system_name=... so governance traces are attributable."
            )
        self._system_name = system_name
        self._use_case = use_case or system_name
        self._gl_client = governlayer_client or GovernLayerClient(
            api_key=governlayer_api_key,
            base_url=governlayer_base_url or "https://www.governlayer.ai",
        )
        self.messages = _GovernedMessages(self.messages, self)

    def _evaluate_governance(self, reasoning_trace: str, llm_response: Any, kwargs: dict) -> None:
        if not reasoning_trace:
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
