"""Simple decorators for governing arbitrary Python functions.

These work independently of LangChain -- any async or sync function can
be governed with a one-line decorator.

Usage
-----
::

    from governlayer import govern, audit_trail, risk_gate

    @govern(system_name="my-bot", api_key="gl_xxx")
    async def generate_response(prompt: str) -> str:
        return await my_llm(prompt)

    @risk_gate(threshold=70, api_key="gl_xxx")
    async def risky_operation(data: str) -> str:
        ...

    @audit_trail(system_name="logger", api_key="gl_xxx")
    async def tracked_call(text: str) -> str:
        ...
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable, TypeVar

from .client import GovernLayerClient
from .types import GovernanceAction, RiskProfile

logger = logging.getLogger("governlayer.decorators")

F = TypeVar("F", bound=Callable[..., Any])


class GovernanceViolationError(RuntimeError):
    """Raised when a decorated function is blocked by governance policy."""

    def __init__(self, action: str, reason: str, decision_id: str) -> None:
        self.action = action
        self.reason = reason
        self.decision_id = decision_id
        super().__init__(f"GovernLayer {action}: {reason} (decision_id={decision_id})")


def _get_input_text(args: tuple, kwargs: dict) -> str:
    """Best-effort extraction of a text argument for the reasoning trace."""
    # Try common keyword names
    for key in ("prompt", "text", "input", "query", "question", "message"):
        if key in kwargs:
            return str(kwargs[key])
    # Fall back to first positional arg
    if args:
        return str(args[0])
    return str(kwargs) if kwargs else ""


def govern(
    system_name: str = "governed-function",
    api_url: str = "https://web-production-bdd26.up.railway.app",
    api_key: str = "",
    use_case: str = "general",
    auto_block: bool = True,
    block_on_escalate: bool = False,
    risk_profile: RiskProfile | None = None,
) -> Callable[[F], F]:
    """Decorator that runs the full governance pipeline around a function.

    The decorated function's first positional argument (or a keyword
    ``prompt``/``text``/``input``) is used as the input trace.  The
    return value is used as the output trace.

    Parameters
    ----------
    system_name:
        AI system name in GovernLayer.
    api_url:
        GovernLayer API base URL.
    api_key:
        ``gl_xxx`` API key or JWT.
    use_case:
        Use-case label.
    auto_block:
        Raise ``GovernanceViolationError`` when the API returns BLOCK.
    block_on_escalate:
        Also block on ESCALATE_HUMAN.
    risk_profile:
        Default risk flags.
    """

    def decorator(fn: F) -> F:
        client = GovernLayerClient(
            api_url=api_url,
            api_key=api_key,
            risk_profile=risk_profile,
        )

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_text = _get_input_text(args, kwargs)

            # Execute the original function
            result = await fn(*args, **kwargs)
            output_text = str(result) if result is not None else ""

            # Run governance
            reasoning_trace = f"INPUT:\n{input_text}\n\nOUTPUT:\n{output_text}"
            try:
                gov = await client.govern(
                    system_name=system_name,
                    reasoning_trace=reasoning_trace,
                    use_case=use_case,
                    ai_decision=output_text[:5000],
                )
            except Exception:
                logger.exception("Governance check failed -- allowing by default")
                return result

            should_block = gov.action == GovernanceAction.BLOCK or (
                block_on_escalate and gov.action == GovernanceAction.ESCALATE_HUMAN
            )
            if should_block and auto_block:
                raise GovernanceViolationError(
                    action=gov.action.value,
                    reason=gov.reason,
                    decision_id=gov.decision_id,
                )

            return result

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_text = _get_input_text(args, kwargs)

            # Execute the original function
            result = fn(*args, **kwargs)
            output_text = str(result) if result is not None else ""

            # Run governance asynchronously
            reasoning_trace = f"INPUT:\n{input_text}\n\nOUTPUT:\n{output_text}"

            async def _govern() -> None:
                try:
                    gov = await client.govern(
                        system_name=system_name,
                        reasoning_trace=reasoning_trace,
                        use_case=use_case,
                        ai_decision=output_text[:5000],
                    )
                except Exception:
                    logger.exception("Governance check failed -- allowing by default")
                    return

                should_block = gov.action == GovernanceAction.BLOCK or (
                    block_on_escalate and gov.action == GovernanceAction.ESCALATE_HUMAN
                )
                if should_block and auto_block:
                    raise GovernanceViolationError(
                        action=gov.action.value,
                        reason=gov.reason,
                        decision_id=gov.decision_id,
                    )

            try:
                loop = asyncio.get_running_loop()
                # Already inside an event loop -- schedule as a task
                loop.create_task(_govern())
            except RuntimeError:
                # No event loop -- run synchronously
                asyncio.run(_govern())

            return result

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def audit_trail(
    system_name: str = "audit-logger",
    api_url: str = "https://web-production-bdd26.up.railway.app",
    api_key: str = "",
    use_case: str = "general",
    risk_profile: RiskProfile | None = None,
) -> Callable[[F], F]:
    """Decorator that logs every call to the GovernLayer ledger.

    Unlike ``@govern``, this **never blocks** -- it only records.
    Governance failures are logged and swallowed.
    """

    def decorator(fn: F) -> F:
        client = GovernLayerClient(
            api_url=api_url,
            api_key=api_key,
            risk_profile=risk_profile,
        )

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_text = _get_input_text(args, kwargs)
            result = await fn(*args, **kwargs)
            output_text = str(result) if result is not None else ""

            reasoning_trace = f"INPUT:\n{input_text}\n\nOUTPUT:\n{output_text}"
            try:
                await client.govern(
                    system_name=system_name,
                    reasoning_trace=reasoning_trace,
                    use_case=use_case,
                    ai_decision=output_text[:5000],
                )
            except Exception:
                logger.exception("Audit trail logging failed")

            return result

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_text = _get_input_text(args, kwargs)
            result = fn(*args, **kwargs)
            output_text = str(result) if result is not None else ""

            reasoning_trace = f"INPUT:\n{input_text}\n\nOUTPUT:\n{output_text}"

            async def _log() -> None:
                try:
                    await client.govern(
                        system_name=system_name,
                        reasoning_trace=reasoning_trace,
                        use_case=use_case,
                        ai_decision=output_text[:5000],
                    )
                except Exception:
                    logger.exception("Audit trail logging failed")

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_log())
            except RuntimeError:
                asyncio.run(_log())

            return result

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def risk_gate(
    threshold: int = 70,
    system_name: str = "risk-gated",
    api_url: str = "https://web-production-bdd26.up.railway.app",
    api_key: str = "",
    use_case: str = "general",
    risk_profile: RiskProfile | None = None,
) -> Callable[[F], F]:
    """Decorator that blocks execution when the risk score exceeds *threshold*.

    Uses the deterministic ``/v1/scan`` endpoint (no LLM, instant) to
    evaluate the input **before** calling the function.  If the scan
    returns a risk score >= *threshold*, ``GovernanceViolationError`` is
    raised and the function is never executed.

    Parameters
    ----------
    threshold:
        Maximum acceptable risk score (0-100, inclusive upper bound).
        Default 70 means scores of 70+ are blocked.
    """

    def decorator(fn: F) -> F:
        client = GovernLayerClient(
            api_url=api_url,
            api_key=api_key,
            risk_profile=risk_profile,
        )

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_text = _get_input_text(args, kwargs)

            try:
                scan = await client.scan(
                    system_name=system_name,
                    reasoning_trace=input_text,
                    use_case=use_case,
                )
            except Exception:
                logger.exception("Risk gate scan failed -- allowing by default")
                return await fn(*args, **kwargs)

            if scan.risk_score >= threshold or scan.is_blocked:
                raise GovernanceViolationError(
                    action=scan.action.value,
                    reason=f"Risk score {scan.risk_score} >= threshold {threshold}",
                    decision_id="",
                )

            return await fn(*args, **kwargs)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_text = _get_input_text(args, kwargs)

            async def _check() -> bool:
                try:
                    scan = await client.scan(
                        system_name=system_name,
                        reasoning_trace=input_text,
                        use_case=use_case,
                    )
                except Exception:
                    logger.exception("Risk gate scan failed -- allowing by default")
                    return False

                if scan.risk_score >= threshold or scan.is_blocked:
                    raise GovernanceViolationError(
                        action=scan.action.value,
                        reason=f"Risk score {scan.risk_score} >= threshold {threshold}",
                        decision_id="",
                    )
                return False

            try:
                loop = asyncio.get_running_loop()
                # Inside an event loop -- can't run synchronously.
                # Create a future; if it blocks, log and allow.
                future = asyncio.ensure_future(_check())
                # We can't block here, so we skip the gate.
                logger.warning(
                    "risk_gate on sync function inside event loop -- "
                    "gate check deferred (function will proceed)"
                )
                _ = future  # noqa: F841
            except RuntimeError:
                asyncio.run(_check())

            return fn(*args, **kwargs)

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator
