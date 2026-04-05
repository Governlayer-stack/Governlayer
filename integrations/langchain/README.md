# governlayer-langchain

Governance middleware for LangChain and LangGraph. Automatically governs every LLM call in your pipeline with drift detection, risk scoring, and immutable audit logging via the [GovernLayer](https://governlayer.ai) API.

## Installation

```bash
pip install governlayer-langchain

# With extras
pip install governlayer-langchain[groq]      # ChatGroq support
pip install governlayer-langchain[openai]     # ChatOpenAI support
pip install governlayer-langchain[langgraph]  # LangGraph node helpers
pip install governlayer-langchain[all]        # Everything
```

For development:

```bash
cd integrations/langchain
pip install -e ".[all,dev]"
```

## Quick Start

### 1. Callback Handler (simplest)

Attach to any LangChain LLM. Governance runs after every call.

```python
from langchain_groq import ChatGroq
from governlayer import GovernLayerCallback

callback = GovernLayerCallback(
    api_key="gl_xxx",
    system_name="support-bot",
    auto_block=True,  # raise GovernanceBlockedError on BLOCK
)

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    callbacks=[callback],
)

# Every invoke/ainvoke is automatically governed
response = await llm.ainvoke("Draft a refund email")
```

### 2. Middleware (pre + post checks)

Wraps any chain with governance. Scans input before the LLM call and runs the full pipeline after.

```python
from governlayer import GovernLayerMiddleware

mw = GovernLayerMiddleware(
    api_key="gl_xxx",
    system_name="legal-drafter",
    risk_threshold=80,    # block risk scores >= 80
    pre_check=True,       # scan input before LLM
    post_check=True,      # full governance after LLM
    block_on_escalate=False,
)

# Wrap any Runnable
governed_chain = mw.wrap_chain(my_chain)
result = await governed_chain.ainvoke("Draft an NDA")
```

#### LangGraph Node

```python
from langgraph.graph import StateGraph

graph = StateGraph(dict)
graph.add_node("governed_llm", mw.as_node(my_llm))
```

### 3. Decorators (framework-agnostic)

Govern any Python function, no LangChain required.

```python
from governlayer import govern, audit_trail, risk_gate

# Full governance pipeline -- blocks on violations
@govern(system_name="my-bot", api_key="gl_xxx")
async def generate_response(prompt: str) -> str:
    return await my_llm(prompt)

# Audit-only -- logs to ledger, never blocks
@audit_trail(system_name="logger", api_key="gl_xxx")
async def tracked_call(text: str) -> str:
    return process(text)

# Risk gate -- blocks BEFORE execution if risk is too high
@risk_gate(threshold=70, api_key="gl_xxx")
async def sensitive_op(query: str) -> str:
    return await dangerous_llm(query)
```

## Configuration

All components accept these common parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_url` | `str` | `https://web-production-bdd26.up.railway.app` | GovernLayer API URL |
| `api_key` | `str` | `""` | API key (`gl_xxx`) or JWT bearer token |
| `system_name` | `str` | `"langchain-app"` | AI system name in GovernLayer |
| `use_case` | `str` | `"general"` | Use-case label for governance context |
| `risk_profile` | `RiskProfile` | low-risk defaults | Risk dimension flags |

### RiskProfile

Configure the 6-axis risk model:

```python
from governlayer import RiskProfile

profile = RiskProfile(
    handles_personal_data=True,
    makes_autonomous_decisions=False,
    used_in_critical_infrastructure=False,
    has_human_oversight=True,
    is_explainable=True,
    has_bias_testing=False,
)

callback = GovernLayerCallback(
    api_key="gl_xxx",
    system_name="my-bot",
    risk_profile=profile,
)
```

### Callback-specific options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `auto_block` | `bool` | `False` | Raise `GovernanceBlockedError` on BLOCK |
| `on_governance_result` | `callable` | `None` | Hook called with every `GovernanceResult` |

### Middleware-specific options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `risk_threshold` | `int` | `0` | Block if risk score >= this value (0 = API-only) |
| `block_on_escalate` | `bool` | `False` | Treat ESCALATE_HUMAN as BLOCK |
| `pre_check` | `bool` | `True` | Run quick scan before LLM call |
| `post_check` | `bool` | `True` | Run full governance after LLM call |
| `blocked_message` | `str` | (default) | Replacement text when blocked |
| `on_event` | `callable` | `None` | Hook called with every `GovernanceEvent` |

## Custom Event Hooks

```python
from governlayer import GovernanceResult, GovernanceEvent

# Callback hook -- fires after every LLM call
def alert_on_block(result: GovernanceResult) -> None:
    if result.is_blocked:
        send_slack_alert(f"BLOCKED: {result.reason}")

callback = GovernLayerCallback(
    api_key="gl_xxx",
    on_governance_result=alert_on_block,
)

# Middleware hook -- fires on pre-check and post-check
def log_event(event: GovernanceEvent) -> None:
    print(f"[{event.phase}] {event.action} risk={event.risk_score}")

mw = GovernLayerMiddleware(
    api_key="gl_xxx",
    on_event=log_event,
)
```

## LCEL Pipeline Composition

The middleware integrates with LangChain Expression Language:

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_groq import ChatGroq
from governlayer import GovernLayerMiddleware

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a compliance advisor."),
    ("human", "{question}"),
])
llm = ChatGroq(model="llama-3.3-70b-versatile")
parser = StrOutputParser()

chain = prompt | llm | parser

mw = GovernLayerMiddleware(api_key="gl_xxx", system_name="advisor")
governed = mw.wrap_chain(chain)

result = await governed.ainvoke({"question": "Explain GDPR Article 22"})
```

## GovernLayer API Reference

The middleware calls these endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/govern` | POST | Full pipeline: drift + risk + decision + ledger |
| `/v1/scan` | POST | Quick deterministic scan (no LLM, instant) |
| `/v1/risk` | POST | 6-dimension risk scoring |
| `/ledger` | GET | Audit trail retrieval |

Authentication via `X-API-Key: gl_xxx` header or `Authorization: Bearer <jwt>`.

## Error Handling

```python
from governlayer import GovernanceBlockedError, GovernanceViolationError

# Callback raises GovernanceBlockedError (when auto_block=True)
try:
    response = await llm.ainvoke("dangerous prompt")
except GovernanceBlockedError as e:
    print(f"Blocked: {e.result.reason}")
    print(f"Decision ID: {e.result.decision_id}")

# Decorators raise GovernanceViolationError
try:
    result = await governed_function("risky input")
except GovernanceViolationError as e:
    print(f"Violation: {e.action} -- {e.reason}")
```

## License

MIT
