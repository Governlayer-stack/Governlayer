# GovernLayer Python SDK

Runtime governance for every AI agent decision. Wrap your OpenAI or Anthropic
client once — every LLM call is automatically pushed through GovernLayer's
`/v1/govern` endpoint for compliance evaluation, drift detection, and risk
scoring. Blocked outputs never reach your users.

## Installation

```bash
# Core SDK
pip install governlayer

# With the OpenAI wrapper
pip install "governlayer[openai]"

# With the Anthropic wrapper
pip install "governlayer[anthropic]"

# Both
pip install "governlayer[all]"
```

From a checkout of the GovernLayer repo:

```bash
pip install -e ./sdk/governlayer-py
```

## Environment Variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `GOVERNLAYER_API_KEY` | Tenant API key (starts with `gl_`) | required |
| `GOVERNLAYER_BASE_URL` | Override governance endpoint | `https://www.governlayer.ai` |

## 1. Raw client

```python
from governlayer import GovernLayerClient, GovernLayerError

client = GovernLayerClient(api_key="gl_...")
result = client.govern(
    system_name="fraud-detector",
    use_case="transaction_review",
    reasoning_trace="Flagged due to velocity anomaly: 14 txns in 90s from new device.",
)
print(result["action"])  # APPROVE | BLOCK | ESCALATE_HUMAN
```

## 2. OpenAI drop-in wrapper

```python
# Before
from openai import OpenAI
client = OpenAI(api_key="sk-...")

# After — two extra kwargs, every chat completion is now governed
from governlayer.openai_wrapper import OpenAI
from governlayer import GovernLayerBlocked

client = OpenAI(
    api_key="sk-...",
    governlayer_api_key="gl_...",
    system_name="fraud-detector",
    use_case="transaction_review",
)

try:
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Should we approve transaction 9af2?"}],
    )
    print(resp.choices[0].message.content)
except GovernLayerBlocked as e:
    # GovernLayer ruled this output non-compliant. e.governance has the full verdict.
    print("Blocked:", e.governance)
```

`ESCALATE_HUMAN` verdicts return normally but emit a warning to stderr so your
ops tooling can pick them up.

## 3. Anthropic drop-in wrapper

```python
from governlayer.anthropic_wrapper import Anthropic
from governlayer import GovernLayerBlocked

client = Anthropic(
    api_key="sk-ant-...",
    governlayer_api_key="gl_...",
    system_name="claims-bot",
    use_case="insurance_claims",
)

resp = client.messages.create(
    model="claude-opus-4-7",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Approve claim 7781?"}],
)
print(resp.content[0].text)
```

## 4. Decorator for custom agents

```python
from governlayer import govern, GovernLayerBlocked

@govern(system_name="claims-bot", use_case="insurance_claims")
def process_claim(claim_data) -> str:
    # ... your agent logic ...
    return f"Approve claim {claim_data['id']} — within policy limit, no fraud indicators."

try:
    decision = process_claim({"id": 7781, "amount": 4200})
except GovernLayerBlocked as e:
    print("Blocked:", e.governance.get("reason"))
```

The decorator captures the function's return value as the `reasoning_trace`,
sends it to GovernLayer, and either returns it, raises `GovernLayerBlocked`,
or returns + warns on `ESCALATE_HUMAN`.

## Verdict semantics

| Action | Behaviour |
| --- | --- |
| `APPROVE` | Returns normally. |
| `ESCALATE_HUMAN` / `ESCALATE` / `REVIEW` | Returns normally + stderr warning. |
| `BLOCK` / `BLOCKED` / `DENY` | Raises `GovernLayerBlocked`. LLM response is attached as `.llm_response`. |

## Exceptions

- `GovernLayerError` — base class for transport and API failures.
- `GovernLayerBlocked` — raised on a `BLOCK` verdict. Has `.governance` (the
  full verdict dict) and `.llm_response` (what would have been returned).

## Examples

See [`examples/openai_example.py`](examples/openai_example.py) and
[`examples/anthropic_example.py`](examples/anthropic_example.py) for working,
runnable scripts.

## Versioning

`0.1.0` — first public release. SDK pins are SemVer; breaking changes bump the
minor while we are pre-1.0.

## License

Apache 2.0. Copyright (c) GovernLayer.
