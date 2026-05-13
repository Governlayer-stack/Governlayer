"""@govern decorator for arbitrary agent functions.

Wraps a function so its return value is treated as the reasoning_trace and
pushed through GovernLayer. BLOCK -> raise. ESCALATE -> stderr warn + return.
APPROVE -> return.
"""
from __future__ import annotations

import functools
import sys
from typing import Any, Callable, Optional

from .client import GovernLayerBlocked, GovernLayerClient

_BLOCK_ACTIONS = {"BLOCK", "BLOCKED", "DENY"}
_ESCALATE_ACTIONS = {"ESCALATE_HUMAN", "ESCALATE", "REVIEW"}


def govern(
    system_name: str,
    use_case: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[GovernLayerClient] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory: ``@govern(system_name=..., use_case=...)``.

    The wrapped function must return a string (the reasoning trace). The
    decorator calls /v1/govern with that trace and either returns the value,
    raises ``GovernLayerBlocked``, or emits a stderr warning for escalation.

    Args:
        system_name: Logical agent/system identifier. Required.
        use_case: Use case tag. Defaults to ``system_name``.
        api_key: Override the GovernLayer API key. Defaults to env var.
        base_url: Override the GovernLayer base URL.
        client: Pre-built ``GovernLayerClient`` (bypasses api_key/base_url).
    """
    effective_use_case = use_case or system_name

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            value = func(*args, **kwargs)
            reasoning_trace = value if isinstance(value, str) else str(value)
            gl = client or GovernLayerClient(
                api_key=api_key,
                base_url=base_url or "https://www.governlayer.ai",
            )
            result = gl.govern(
                system_name=system_name,
                use_case=effective_use_case,
                reasoning_trace=reasoning_trace,
                function=getattr(func, "__qualname__", func.__name__),
            )
            action = str(result.get("action", "")).upper()
            if action in _BLOCK_ACTIONS:
                raise GovernLayerBlocked(
                    f"GovernLayer blocked function '{func.__name__}' "
                    f"for system '{system_name}': {result.get('reason', result)}",
                    governance=result,
                    llm_response=value,
                )
            if action in _ESCALATE_ACTIONS:
                sys.stderr.write(
                    f"[governlayer] ESCALATE_HUMAN for '{func.__name__}' "
                    f"(system '{system_name}'): {result.get('reason', 'human review required')}\n"
                )
            return value

        return wrapper

    return decorator
