"""LangChain callback handler that governs every LLM call transparently.

Usage
-----
::

    from governlayer import GovernLayerCallback

    callback = GovernLayerCallback(
        api_key="gl_xxx",
        system_name="support-bot",
        auto_block=True,
    )
    llm = ChatGroq(callbacks=[callback])
    llm.invoke("Draft a legal notice")

The handler fires governance checks **asynchronously** so it never blocks
the chain when ``auto_block=False``.  When ``auto_block=True`` it raises
``GovernanceBlockedError`` if the API returns ``BLOCK``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler

from .client import GovernLayerClient
from .types import GovernanceAction, GovernanceResult, RiskProfile

logger = logging.getLogger("governlayer.callback")


class GovernanceBlockedError(RuntimeError):
    """Raised when a governance check returns BLOCK and auto_block is enabled."""

    def __init__(self, result: GovernanceResult) -> None:
        self.result = result
        super().__init__(
            f"GovernLayer BLOCKED: {result.reason} "
            f"(decision_id={result.decision_id}, drift={result.drift_coefficient})"
        )


class GovernLayerCallback(AsyncCallbackHandler):
    """Async LangChain callback that sends every LLM call through GovernLayer.

    Parameters
    ----------
    api_url:
        GovernLayer instance URL.
    api_key:
        ``gl_xxx`` API key or JWT bearer token.
    system_name:
        Name registered in GovernLayer for this AI system.
    use_case:
        Default use-case label (overridable via ``metadata["use_case"]``).
    auto_block:
        If ``True``, raise ``GovernanceBlockedError`` when the API returns
        ``BLOCK``.  If ``False`` (default), log a warning and continue.
    risk_profile:
        Default risk flags for the system.
    on_governance_result:
        Optional hook called with every ``GovernanceResult``.  Useful for
        custom alerting or metrics.
    """

    raise_error = True  # LangChain will propagate our exceptions

    def __init__(
        self,
        api_url: str = "https://www.governlayer.ai",
        api_key: str = "",
        system_name: str = "langchain-app",
        use_case: str = "general",
        auto_block: bool = False,
        risk_profile: RiskProfile | None = None,
        on_governance_result: Any | None = None,
    ) -> None:
        super().__init__()
        self.system_name = system_name
        self.use_case = use_case
        self.auto_block = auto_block
        self.on_governance_result = on_governance_result
        self._client = GovernLayerClient(
            api_url=api_url,
            api_key=api_key,
            risk_profile=risk_profile,
        )
        # Per-run tracking: run_id -> metadata dict
        self._runs: dict[str, dict[str, Any]] = {}

    # -- helpers ----------------------------------------------------------

    def _run_key(self, run_id: UUID) -> str:
        return str(run_id)

    async def _safe_govern(
        self,
        reasoning_trace: str,
        use_case: str,
        ai_decision: str = "",
    ) -> GovernanceResult | None:
        """Call the govern endpoint; swallow transport errors."""
        try:
            return await self._client.govern(
                system_name=self.system_name,
                reasoning_trace=reasoning_trace,
                use_case=use_case,
                ai_decision=ai_decision,
            )
        except Exception:
            logger.exception("GovernLayer govern call failed")
            return None

    async def _safe_scan(
        self,
        reasoning_trace: str,
        use_case: str,
    ) -> dict[str, Any] | None:
        """Call the scan endpoint; swallow transport errors."""
        try:
            result = await self._client.scan(
                system_name=self.system_name,
                reasoning_trace=reasoning_trace,
                use_case=use_case,
            )
            return result.raw
        except Exception:
            logger.exception("GovernLayer scan call failed")
            return None

    # -- LangChain callback interface -------------------------------------

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Record the input prompt and timestamp for later governance check."""
        meta = metadata or {}
        self._runs[self._run_key(run_id)] = {
            "prompts": prompts,
            "start_time": time.time(),
            "use_case": meta.get("use_case", self.use_case),
            "metadata": meta,
            "model": serialized.get("kwargs", {}).get("model_name", "unknown"),
        }
        logger.debug(
            "on_llm_start: run=%s model=%s prompts=%d",
            run_id,
            serialized.get("kwargs", {}).get("model_name"),
            len(prompts),
        )

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle chat-model starts (ChatGroq, ChatOpenAI, etc.)."""
        meta = metadata or {}
        # Flatten messages into a single string for the reasoning trace
        flat_parts: list[str] = []
        for message_list in messages:
            for msg in message_list:
                content = getattr(msg, "content", str(msg))
                role = getattr(msg, "type", "unknown")
                flat_parts.append(f"[{role}] {content}")

        self._runs[self._run_key(run_id)] = {
            "prompts": flat_parts,
            "start_time": time.time(),
            "use_case": meta.get("use_case", self.use_case),
            "metadata": meta,
            "model": serialized.get("kwargs", {}).get("model_name", "unknown"),
        }
        logger.debug(
            "on_chat_model_start: run=%s messages=%d",
            run_id,
            sum(len(ml) for ml in messages),
        )

    async def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """After the LLM responds, govern the input+output pair."""
        key = self._run_key(run_id)
        run_data = self._runs.pop(key, None)
        if run_data is None:
            logger.warning("on_llm_end for unknown run %s", run_id)
            return

        # Extract the generated text
        output_text = ""
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    output_text += getattr(gen, "text", str(gen))

        input_text = "\n".join(run_data["prompts"])
        reasoning_trace = f"INPUT:\n{input_text}\n\nOUTPUT:\n{output_text}"
        use_case = run_data["use_case"]
        elapsed = time.time() - run_data["start_time"]

        logger.info(
            "Governing LLM call: system=%s model=%s elapsed=%.2fs",
            self.system_name,
            run_data["model"],
            elapsed,
        )

        result = await self._safe_govern(
            reasoning_trace=reasoning_trace,
            use_case=use_case,
            ai_decision=output_text[:5000],
        )

        if result is None:
            logger.warning("Governance check unavailable -- allowing by default")
            return

        # Notify custom hook
        if self.on_governance_result is not None:
            try:
                ret = self.on_governance_result(result)
                if asyncio.iscoroutine(ret):
                    await ret
            except Exception:
                logger.exception("on_governance_result hook failed")

        if result.action == GovernanceAction.BLOCK:
            logger.warning(
                "BLOCKED by GovernLayer: %s (decision_id=%s)",
                result.reason,
                result.decision_id,
            )
            if self.auto_block:
                raise GovernanceBlockedError(result)

        elif result.action == GovernanceAction.ESCALATE_HUMAN:
            logger.warning(
                "ESCALATED by GovernLayer: %s (decision_id=%s)",
                result.reason,
                result.decision_id,
            )

        else:
            logger.info(
                "APPROVED by GovernLayer: decision_id=%s risk=%s drift=%.3f",
                result.decision_id,
                result.risk_score,
                result.drift_coefficient,
            )

    async def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Log LLM errors to GovernLayer as incident traces."""
        key = self._run_key(run_id)
        run_data = self._runs.pop(key, None)
        input_text = "\n".join(run_data["prompts"]) if run_data else "<unknown>"
        use_case = run_data["use_case"] if run_data else self.use_case

        reasoning_trace = (
            f"INPUT:\n{input_text}\n\n"
            f"ERROR:\n{type(error).__name__}: {error}"
        )
        logger.error("LLM error for run %s: %s", run_id, error)

        # Fire-and-forget scan to record the incident
        await self._safe_scan(reasoning_trace=reasoning_trace, use_case=use_case)

    # -- cleanup ----------------------------------------------------------

    async def close(self) -> None:
        """Release the underlying HTTP client."""
        await self._client.close()
