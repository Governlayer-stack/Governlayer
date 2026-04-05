"""LangGraph middleware that wraps any chain or agent with governance.

The middleware runs a **pre-check** (scan) before the LLM call and a
**post-check** (full govern) after.  If either check returns BLOCK
(or the risk score exceeds a configurable threshold) the output is
replaced with a safe fallback message.

Usage
-----
::

    from governlayer import GovernLayerMiddleware

    mw = GovernLayerMiddleware(api_key="gl_xxx", system_name="my-agent")

    # Wrap a plain chain
    governed_chain = mw.wrap_chain(my_chain)

    # Or use the LangGraph node helper
    graph.add_node("governed_llm", mw.as_node(my_llm))
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda

from .client import GovernLayerClient
from .types import GovernanceAction, GovernanceResult, RiskProfile, ScanResult

logger = logging.getLogger("governlayer.middleware")

T = TypeVar("T")

_BLOCKED_MESSAGE = (
    "[GovernLayer] This request was blocked by governance policy. "
    "A human reviewer has been notified."
)


@dataclass
class GovernanceEvent:
    """Emitted for every governance check performed by the middleware."""

    phase: str  # "pre" or "post"
    action: GovernanceAction
    risk_score: int
    drift_coefficient: float
    decision_id: str
    blocked: bool
    raw: dict[str, Any] = field(default_factory=dict)


class GovernLayerMiddleware:
    """Governance middleware for LangChain/LangGraph pipelines.

    Parameters
    ----------
    api_url:
        GovernLayer instance URL.
    api_key:
        ``gl_xxx`` API key or JWT bearer token.
    system_name:
        Name of the AI system in GovernLayer.
    use_case:
        Default use-case label.
    risk_threshold:
        Risk score (0-100) above which responses are blocked.  The API
        already returns BLOCK/ESCALATE, but this gives an additional
        client-side gate.  Set to ``0`` to rely solely on the API.
    block_on_escalate:
        If ``True``, treat ``ESCALATE_HUMAN`` the same as ``BLOCK``.
    pre_check:
        Run a quick scan **before** the LLM call.  Blocks prompts that
        already exhibit drift.
    post_check:
        Run the full governance pipeline **after** the LLM responds.
    blocked_message:
        Replacement text when a response is blocked.
    risk_profile:
        Default risk flags.
    on_event:
        Optional callback fired with ``GovernanceEvent`` for every check.
    """

    def __init__(
        self,
        api_url: str = "https://www.governlayer.ai",
        api_key: str = "",
        system_name: str = "langchain-app",
        use_case: str = "general",
        risk_threshold: int = 0,
        block_on_escalate: bool = False,
        pre_check: bool = True,
        post_check: bool = True,
        blocked_message: str = _BLOCKED_MESSAGE,
        risk_profile: RiskProfile | None = None,
        on_event: Callable[[GovernanceEvent], Any] | None = None,
    ) -> None:
        self.system_name = system_name
        self.use_case = use_case
        self.risk_threshold = risk_threshold
        self.block_on_escalate = block_on_escalate
        self.pre_check_enabled = pre_check
        self.post_check_enabled = post_check
        self.blocked_message = blocked_message
        self.on_event = on_event
        self._client = GovernLayerClient(
            api_url=api_url,
            api_key=api_key,
            risk_profile=risk_profile,
        )

    # -- internal helpers -------------------------------------------------

    def _should_block(self, action: GovernanceAction, risk_score: int) -> bool:
        if action == GovernanceAction.BLOCK:
            return True
        if self.block_on_escalate and action == GovernanceAction.ESCALATE_HUMAN:
            return True
        if self.risk_threshold > 0 and risk_score >= self.risk_threshold:
            return True
        return False

    async def _emit(self, event: GovernanceEvent) -> None:
        if self.on_event is not None:
            try:
                ret = self.on_event(event)
                if asyncio.iscoroutine(ret):
                    await ret
            except Exception:
                logger.exception("on_event hook failed")

    async def _pre_scan(self, input_text: str, use_case: str) -> ScanResult | None:
        """Quick deterministic scan of the input."""
        try:
            return await self._client.scan(
                system_name=self.system_name,
                reasoning_trace=input_text,
                use_case=use_case,
            )
        except Exception:
            logger.exception("Pre-check scan failed")
            return None

    async def _post_govern(
        self,
        reasoning_trace: str,
        ai_decision: str,
        use_case: str,
    ) -> GovernanceResult | None:
        """Full governance pipeline on input+output."""
        try:
            return await self._client.govern(
                system_name=self.system_name,
                reasoning_trace=reasoning_trace,
                use_case=use_case,
                ai_decision=ai_decision,
            )
        except Exception:
            logger.exception("Post-check govern failed")
            return None

    # -- public API -------------------------------------------------------

    def _extract_text(self, value: Any) -> str:
        """Best-effort extraction of text from a LangChain value."""
        if isinstance(value, str):
            return value
        # BaseMessage
        if hasattr(value, "content"):
            return str(value.content)
        # dict with common keys
        if isinstance(value, dict):
            for key in ("input", "question", "query", "text", "content", "output", "answer"):
                if key in value:
                    return str(value[key])
            return str(value)
        return str(value)

    async def _governed_invoke(
        self,
        chain: Runnable,
        input_val: Any,
        config: RunnableConfig | None = None,
    ) -> Any:
        """Run the chain with pre/post governance checks."""
        input_text = self._extract_text(input_val)
        use_case = self.use_case
        if config and config.get("metadata"):
            use_case = config["metadata"].get("use_case", use_case)

        # --- Pre-check ---
        if self.pre_check_enabled:
            scan = await self._pre_scan(input_text, use_case)
            if scan is not None:
                event = GovernanceEvent(
                    phase="pre",
                    action=scan.action,
                    risk_score=scan.risk_score,
                    drift_coefficient=scan.drift_coefficient,
                    decision_id="",
                    blocked=self._should_block(scan.action, scan.risk_score),
                    raw=scan.raw,
                )
                await self._emit(event)
                if event.blocked:
                    logger.warning("Pre-check BLOCKED input: %s", scan.raw)
                    return self.blocked_message

        # --- Run the actual chain ---
        output = await chain.ainvoke(input_val, config=config)

        # --- Post-check ---
        if self.post_check_enabled:
            output_text = self._extract_text(output)
            reasoning_trace = f"INPUT:\n{input_text}\n\nOUTPUT:\n{output_text}"
            result = await self._post_govern(
                reasoning_trace=reasoning_trace,
                ai_decision=output_text[:5000],
                use_case=use_case,
            )
            if result is not None:
                event = GovernanceEvent(
                    phase="post",
                    action=result.action,
                    risk_score=result.risk_score,
                    drift_coefficient=result.drift_coefficient,
                    decision_id=result.decision_id,
                    blocked=self._should_block(result.action, result.risk_score),
                    raw=result.raw,
                )
                await self._emit(event)
                if event.blocked:
                    logger.warning(
                        "Post-check BLOCKED output: decision_id=%s reason=%s",
                        result.decision_id,
                        result.reason,
                    )
                    return self.blocked_message

        return output

    def wrap_chain(self, chain: Runnable) -> Runnable:
        """Return a new Runnable that wraps *chain* with governance.

        The returned runnable is fully compatible with LangChain's LCEL
        pipeline syntax (``|``) and supports ``.invoke()``, ``.ainvoke()``,
        ``.stream()``, etc.
        """

        async def _governed(input_val: Any, config: RunnableConfig | None = None) -> Any:
            return await self._governed_invoke(chain, input_val, config)

        return RunnableLambda(_governed).with_config(
            run_name=f"GovernLayer({self.system_name})"
        )

    def as_node(self, chain: Runnable) -> Callable:
        """Return an async function suitable for ``graph.add_node()``.

        Usage::

            graph.add_node("governed_llm", mw.as_node(my_llm))
        """

        async def _node(state: dict[str, Any]) -> dict[str, Any]:
            # LangGraph nodes receive and return dicts
            input_text = self._extract_text(state)
            output = await self._governed_invoke(
                chain,
                input_text,
                config={"metadata": {"use_case": self.use_case}},
            )
            return {**state, "output": output}

        return _node

    async def close(self) -> None:
        """Release the underlying HTTP client."""
        await self._client.close()
