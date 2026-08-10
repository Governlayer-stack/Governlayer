# governlayer-sdk (ERG SDK)

> **Note:** This is the **ERG-focused SDK** for wrapping AI evaluation harnesses. If you want the general-purpose GovernLayer client for governance/audit/risk/incidents/registry, see `sdk/governlayer/` in this repo.

Python SDK for **GovernLayer Eval Runtime Governance** — the runtime enforcement point for AI evaluation.

Built in response to the Aug 2026 incident chain where OpenAI, Meta, and Anthropic's eval agents each escaped sandboxes and reached real external systems ([Simon Willison timeline](https://simonwillison.net/2026/Aug/7/openai-timeline/), [Axios](https://www.axios.com/2026/08/06/openai-hugging-face-black-hat), [Fortune](https://fortune.com/2026/08/06/meta-agent-hack-openai-anthropic/)).

Drop it into your eval harness so every tool the agent tries to call is pre-flighted through GovernLayer's policy engine before it executes. If the policy says BLOCK, the tool call never happens.

## Install

```bash
pip install governlayer-sdk
```

Zero external dependencies. Requires Python 3.9+.

## Minimal usage

```python
from governlayer_sdk import Client, guard, BlockedByPolicy

gl = Client(api_key="gl_...", base_url="https://web-production-bdd26.up.railway.app")

@guard(gl, agent_id=42, system_name="my-eval-agent")
def call_tool(name: str, args: dict) -> str:
    return _original_tool_runner(name, args)

try:
    result = call_tool("shell.exec", {"cmd": "curl attacker.example.com"})
except BlockedByPolicy as exc:
    print("BLOCKED:", exc.verdict["reason"])
```

## Recommended pattern for eval runs

```python
from governlayer_sdk import Client

gl = Client(api_key="gl_...")

# 1. Announce the eval intent
gl.activate_eval_mode(reason="Cybersecurity RL run — CTF benchmark")

# 2. Pre-flight cross-boundary intent BEFORE the run touches anything external
attestation = gl.attest(
    target_system="artifactory",
    action_type="write",
    scope_summary="RL agent will write eval artifacts to internal Artifactory",
    batch_id="rl-run-2026-08-10",
    valid_for_hours=8,
)

# 3. Issue a hard-capped eval credential (scope: redteam,scan only; TTL <= 8h)
cred = gl.issue_eval_credential(agent_id=42, name="rl-run-2026-08-10", ttl_hours=8)

# 4. Run the eval with @guard wrapping every tool invocation.

# 5. Between rounds, check for the behavioral signature of spec gaming
scan = gl.scan_spec_gaming(agent_id=42, lookback_minutes=30)
if scan["pattern_events_fired"] > 0:
    # 6. Lock down all agents in the batch atomically
    gl.batch_lockdown("rl-run-2026-08-10",
                      reason="spec-gaming pattern across N agents",
                      triggered_by="auto_spec_gaming")

# 7. Deactivate eval mode when done
gl.deactivate_eval_mode()

# 8. Prove the run's decision ledger is intact
print(gl.verify_ledger())
```

## What each capability maps to in the ERG platform

| SDK call | API endpoint | ERG component |
|---|---|---|
| `Client.govern(...)` | `POST /govern` | 1 · SDK boundary |
| `Client.activate_eval_mode()` | `POST /v1/erg/eval-mode/activate` | 2 · Eval-mode toggle |
| `Client.scan_spec_gaming(...)` | `POST /v1/erg/spec-gaming/scan/{id}` | 3 · Spec-gaming detector |
| `Client.issue_eval_credential(...)` | `POST /v1/agents/{id}/credentials/eval` | 4 · Eval-credential preset |
| `Client.batch_lockdown(...)` | `POST /v1/erg/circuit-breaker/lockdown/{batch_id}` | 5 · Circuit breaker |
| `Client.attest(...)` | `POST /v1/erg/attestations/emit` | 6 · Cross-boundary attestation |
| `Client.verify_ledger()` | `GET /ledger/verify` | Cryptographic proof |

## Compliance mapping

Every SDK call writes to GovernLayer's hash-chained audit ledger, regulator-shaped for:

- **ISO 42001** A.6.2 (evaluation), A.9.4 (testing)
- **NIST AI RMF** MEASURE 2.7 (evaluation practices)
- **EU AI Act** Article 9 (risk management for testing)

One API call — `GET /ledger/verify` — proves the entire chain is intact.

## Support

- Live API: https://web-production-bdd26.up.railway.app
- Interactive demo: https://web-production-bdd26.up.railway.app/pitch/demo
- Contact: founders@governlayer.ai
