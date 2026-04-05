"""Basic usage examples for governlayer-langchain.

Run with:
    export GROQ_API_KEY=gsk_xxx
    export GOVERNLAYER_API_KEY=gl_xxx
    python examples/basic_usage.py
"""

from __future__ import annotations

import asyncio
import os

# ---------------------------------------------------------------------------
# Example 1: Callback handler -- govern every LLM call automatically
# ---------------------------------------------------------------------------


async def callback_example() -> None:
    """Attach GovernLayerCallback to any LangChain LLM."""
    from langchain_groq import ChatGroq

    from governlayer import GovernLayerCallback

    api_key = os.environ.get("GOVERNLAYER_API_KEY", "")
    groq_key = os.environ.get("GROQ_API_KEY", "")

    # Create the callback -- it will POST to /v1/govern after every LLM call
    callback = GovernLayerCallback(
        api_key=api_key,
        system_name="support-bot",
        use_case="customer_support",
        auto_block=False,  # log-only mode; set True to raise on BLOCK
    )

    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=groq_key,
        callbacks=[callback],
    )

    response = await llm.ainvoke(
        "Explain our refund policy to a frustrated customer",
        config={"metadata": {"use_case": "customer_support"}},
    )
    print(f"[Callback] Response: {response.content[:200]}...")
    await callback.close()


# ---------------------------------------------------------------------------
# Example 2: Middleware -- wrap a chain with pre/post governance checks
# ---------------------------------------------------------------------------


async def middleware_example() -> None:
    """Wrap any chain with GovernLayerMiddleware for full pre+post checks."""
    from langchain_groq import ChatGroq

    from governlayer import GovernLayerMiddleware

    api_key = os.environ.get("GOVERNLAYER_API_KEY", "")
    groq_key = os.environ.get("GROQ_API_KEY", "")

    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=groq_key)

    mw = GovernLayerMiddleware(
        api_key=api_key,
        system_name="legal-drafter",
        use_case="legal",
        risk_threshold=80,  # block anything with risk score >= 80
        pre_check=True,     # scan input before LLM call
        post_check=True,    # full governance after LLM responds
    )

    governed_llm = mw.wrap_chain(llm)

    # This goes through pre-scan -> LLM -> post-govern automatically
    result = await governed_llm.ainvoke("Draft a standard NDA clause")
    print(f"[Middleware] Result: {result}")
    await mw.close()


# ---------------------------------------------------------------------------
# Example 3: Decorators -- govern any Python function
# ---------------------------------------------------------------------------


async def decorator_example() -> None:
    """Use @govern, @audit_trail, and @risk_gate on plain functions."""
    from governlayer import audit_trail, govern, risk_gate

    api_key = os.environ.get("GOVERNLAYER_API_KEY", "")

    # @govern -- full pipeline, blocks on violations
    @govern(system_name="analysis-bot", api_key=api_key, auto_block=True)
    async def analyze_document(text: str) -> str:
        # Simulate LLM call
        return f"Analysis of: {text[:50]}... -- Compliant with all policies."

    # @audit_trail -- just records to ledger, never blocks
    @audit_trail(system_name="logger-bot", api_key=api_key)
    async def log_interaction(prompt: str) -> str:
        return f"Logged: {prompt}"

    # @risk_gate -- blocks before execution if risk is too high
    @risk_gate(threshold=70, system_name="gated-bot", api_key=api_key)
    async def sensitive_operation(query: str) -> str:
        return f"Processed: {query}"

    result1 = await analyze_document("Annual compliance report Q4 2025")
    print(f"[govern] {result1}")

    result2 = await log_interaction("User asked about data retention")
    print(f"[audit_trail] {result2}")

    result3 = await sensitive_operation("Standard lookup query")
    print(f"[risk_gate] {result3}")


# ---------------------------------------------------------------------------
# Example 4: Custom event hooks
# ---------------------------------------------------------------------------


async def event_hooks_example() -> None:
    """Use on_governance_result and on_event hooks for custom alerting."""
    from langchain_groq import ChatGroq

    from governlayer import (
        GovernanceEvent,
        GovernanceResult,
        GovernLayerCallback,
        GovernLayerMiddleware,
    )

    api_key = os.environ.get("GOVERNLAYER_API_KEY", "")
    groq_key = os.environ.get("GROQ_API_KEY", "")

    # Hook for the callback
    def on_result(result: GovernanceResult) -> None:
        print(f"  [Hook] Decision: {result.action.value} | Risk: {result.risk_score}")

    callback = GovernLayerCallback(
        api_key=api_key,
        system_name="monitored-bot",
        on_governance_result=on_result,
    )

    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=groq_key,
        callbacks=[callback],
    )

    await llm.ainvoke("What is the capital of France?")

    # Hook for the middleware
    def on_event(event: GovernanceEvent) -> None:
        emoji = "PRE" if event.phase == "pre" else "POST"
        print(f"  [{emoji}] {event.action.value} | Risk: {event.risk_score} | Blocked: {event.blocked}")

    mw = GovernLayerMiddleware(
        api_key=api_key,
        system_name="monitored-bot",
        on_event=on_event,
    )

    governed = mw.wrap_chain(llm)
    await governed.ainvoke("Summarise the EU AI Act")

    await callback.close()
    await mw.close()


# ---------------------------------------------------------------------------
# Example 5: LCEL pipeline composition
# ---------------------------------------------------------------------------


async def lcel_pipeline_example() -> None:
    """Compose governed chains using LangChain Expression Language."""
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_groq import ChatGroq

    from governlayer import GovernLayerMiddleware

    api_key = os.environ.get("GOVERNLAYER_API_KEY", "")
    groq_key = os.environ.get("GROQ_API_KEY", "")

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a compliance advisor. Be concise."),
        ("human", "{question}"),
    ])
    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=groq_key)
    parser = StrOutputParser()

    # Build an LCEL chain
    chain = prompt | llm | parser

    # Wrap the entire chain with governance
    mw = GovernLayerMiddleware(
        api_key=api_key,
        system_name="compliance-advisor",
        use_case="regulatory",
    )
    governed_chain = mw.wrap_chain(chain)

    result = await governed_chain.ainvoke({"question": "What is GDPR Article 22?"})
    print(f"[LCEL] {result}")
    await mw.close()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def main() -> None:
    print("=" * 60)
    print("GovernLayer LangChain Integration Examples")
    print("=" * 60)

    examples = [
        ("Callback Handler", callback_example),
        ("Middleware", middleware_example),
        ("Decorators", decorator_example),
        ("Event Hooks", event_hooks_example),
        ("LCEL Pipeline", lcel_pipeline_example),
    ]

    for name, fn in examples:
        print(f"\n--- {name} ---")
        try:
            await fn()
        except ImportError as e:
            print(f"  Skipped (missing dependency): {e}")
        except Exception as e:
            print(f"  Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
