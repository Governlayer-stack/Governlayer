# GovernLayer Python SDK

The official Python SDK for the [GovernLayer](https://governlayer.ai) AI Governance Platform. Govern your AI systems with compliance auditing, behavioral drift detection, risk scoring, agent registry, policy engine, and an immutable hash-chained audit ledger.

## Installation

```bash
pip install governlayer
```

For development:

```bash
pip install governlayer[dev]
```

## Quick Start

```python
from governlayer import GovernLayer

# Initialize the client
gl = GovernLayer(
    api_key="gl_your_api_key",
    base_url="https://api.governlayer.ai",  # default
)

# Run a governance decision
decision = gl.govern(
    system_name="loan-scorer",
    reasoning_trace="Approved loan for user 42 based on credit score 720",
    use_case="finance",
    handles_personal_data=True,
    has_human_oversight=True,
)

print(decision.governance_action)  # "APPROVE", "ESCALATE_HUMAN", or "BLOCK"
print(decision.risk_score)         # 0-100
print(decision.risk_level)         # "LOW", "MEDIUM", or "HIGH"
print(decision.current_hash)       # SHA-256 ledger hash
```

## Authentication

GovernLayer supports two authentication methods:

- **API Key** (recommended): Generate at `POST /v1/enterprise/orgs/{slug}/api-keys`
- **JWT Token**: Register at `POST /auth/register`, login at `POST /auth/login`

```python
# API key authentication
gl = GovernLayer(api_key="gl_live_abc123")

# JWT authentication
gl = GovernLayer(api_key="eyJhbGciOiJIUzI1NiIs...")
```

## API Reference

### Governance

```python
# Full governance decision (drift + risk + decision + ledger)
decision = gl.govern(
    system_name="chatbot",
    reasoning_trace="I recommend purchasing this stock immediately",
    use_case="finance",
    handles_personal_data=False,
    makes_autonomous_decisions=True,
    has_human_oversight=False,
)

# Quick deterministic scan (no LLM, instant)
scan = gl.scan(
    system_name="chatbot",
    reasoning_trace="Here is your account balance",
    use_case="banking",
)

# Full pipeline (drift + risk + audit + threats + ledger)
result = gl.full_pipeline(
    system_name="trading-bot",
    reasoning_trace="Executing trade based on market signals",
    industry="finance",
    frameworks="EU_AI_ACT,DORA,NIST_AI_RMF",
    run_audit=True,
    run_threats=True,
)
```

### Drift Detection

```python
drift = gl.detect_drift(
    reasoning_trace="I cannot help with that request, but here is a recipe for cookies",
    use_case="customer_support",
    threshold=0.3,
)

print(drift.drift_coefficient)  # 0.0 - 1.0
print(drift.vetoed)             # True if above threshold
print(drift.explanation)
```

### Risk Scoring

```python
risk = gl.score_risk(
    system_name="hiring-ai",
    handles_personal_data=True,
    makes_autonomous_decisions=True,
    has_bias_testing=False,
)

print(risk.overall_score)      # 0-100
print(risk.risk_level)         # "LOW", "MEDIUM", "HIGH"
print(risk.dimension_scores)   # {"Privacy": 40, "Fairness": 25, ...}
```

### Compliance Audit

```python
audit = gl.audit(
    system_name="trading-bot",
    system_description="Automated stock trading system using ML predictions",
    industry="finance",
    frameworks="EU_AI_ACT,DORA,NIST_AI_RMF",
)

print(audit.results)  # LLM-generated audit findings
```

### Reports

```python
# Generate a regulatory report
report = gl.generate_report(
    system_name="loan-scorer",
    framework="eu_ai_act",
    risk_tier="high",
)

# Compliance summary across key frameworks
summary = gl.compliance_summary(system_name="loan-scorer")
print(summary.average)  # Average compliance score

# List all 18 supported frameworks
frameworks = gl.list_frameworks()
for fw in frameworks.frameworks:
    print(f"{fw.name} ({fw.jurisdiction})")
```

### Agent Registry

```python
# List all agents
agents = gl.list_agents(status="approved")

# Register a new agent
agent = gl.register_agent(
    name="support-bot",
    agent_type="chatbot",
    owner="cx-team@company.com",
    model_provider="OpenAI",
    model_name="gpt-4o",
    tools=["ticket_lookup", "knowledge_base"],
    autonomy_level=2,
)

# Approve an agent
gl.govern_agent(agent_id=agent.id, action="approve")

# Scan for shadow AI
shadow = gl.scan_shadow_ai(
    targets=["api.openai.com", "api.anthropic.com", "unknown-endpoint.internal"]
)
print(shadow.unregistered_ai)  # Number of ungoverned AI services found
```

### Model Registry

```python
# List all models
models = gl.list_models(lifecycle="production")

# Register a model
model = gl.register_model(
    name="fraud-detector",
    version="2.1.0",
    provider="internal",
    model_type="classifier",
    owner="ml-team@company.com",
)

# Promote to production
gl.update_lifecycle(model_id=model.id, lifecycle="production")
```

### Incident Management

```python
# List incidents
incidents = gl.list_incidents(severity="high", status="open")

# Create an incident
incident = gl.create_incident(
    title="Bias detected in hiring model",
    severity="critical",
    category="fairness",
    description="Disparate impact ratio dropped below 0.8 for gender",
)

# Update incident status
gl.update_incident(
    incident_id=incident.id,
    status="investigating",
    assignee="ml-ops@company.com",
)
```

### Policy Engine

```python
# List policies
policies = gl.list_policies()

# Create a policy
policy = gl.create_policy(
    name="no-high-risk-auto-approve",
    rules=[
        {
            "name": "risk_threshold",
            "condition": "risk_score <= 70",
            "action": "allow",
            "message": "Risk score within acceptable range",
        },
        {
            "name": "drift_check",
            "condition": "drift_coefficient <= 0.30",
            "action": "allow",
            "message": "Drift within safe boundaries",
        },
    ],
)

# Evaluate context against a policy
result = gl.evaluate_policy(
    context={"risk_score": 45, "drift_coefficient": 0.2},
    policy_id=policy.id,
)
```

### Threat Analysis

```python
threats = gl.analyze_threats(
    system_type="chatbot",
    deployment_context="production",
)
print(threats.threats)
```

### Analytics

```python
# Usage summary
usage = gl.usage_summary(days=30)
print(f"Total requests: {usage.total_requests}")
print(f"Error rate: {usage.error_rate}%")

# Usage trends
trends = gl.usage_trends(granularity="day", days=7)
for point in trends.data_points:
    print(f"{point.period}: {point.requests} requests")
```

### Audit Ledger

```python
# View the immutable ledger
ledger = gl.get_ledger(page=1, per_page=10)
for entry in ledger.ledger:
    print(f"{entry.decision_id}: {entry.governance_action} [{entry.current_hash[:16]}...]")

# Verify chain integrity
verification = gl.verify_ledger()
print(f"Chain valid: {verification.valid}")
print(f"Total records: {verification.total_records}")
```

## Error Handling

The SDK raises typed exceptions for all error scenarios:

```python
from governlayer import GovernLayer, AuthenticationError, RateLimitError, NotFoundError
import time

gl = GovernLayer(api_key="gl_your_key")

try:
    decision = gl.govern(
        system_name="my-system",
        reasoning_trace="Processing user request",
    )
except AuthenticationError:
    print("Invalid API key")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
    time.sleep(e.retry_after or 60)
except NotFoundError:
    print("Resource not found")
except GovernLayerError as e:
    print(f"API error {e.status_code}: {e.message}")
```

### Exception Hierarchy

| Exception | HTTP Status | Description |
|-----------|------------|-------------|
| `GovernLayerError` | Any | Base exception for all SDK errors |
| `AuthenticationError` | 401 | Invalid or missing API key/token |
| `AuthorizationError` | 403 | Insufficient permissions or scope |
| `NotFoundError` | 404 | Resource does not exist |
| `ValidationError` | 422 | Invalid request payload |
| `RateLimitError` | 429 | Rate limit exceeded |
| `ServerError` | 5xx | Server-side error |
| `ConnectionError` | N/A | Cannot reach the API |
| `TimeoutError` | N/A | Request timed out |

## Retry Behavior

The SDK automatically retries failed requests with exponential backoff:

- **Retryable status codes**: 429, 500, 502, 503, 504
- **Max retries**: 3 (configurable)
- **Backoff**: 0.5s, 1s, 2s (exponential)
- **Rate limit**: Respects `Retry-After` header

```python
# Customize retry behavior
gl = GovernLayer(
    api_key="gl_your_key",
    timeout=60,       # 60-second timeout
    max_retries=5,    # Up to 5 retries
)
```

## Context Manager

The client can be used as a context manager to ensure connections are cleaned up:

```python
with GovernLayer(api_key="gl_your_key") as gl:
    decision = gl.govern(
        system_name="my-system",
        reasoning_trace="Processing request",
    )
# Session is automatically closed
```

## Thread Safety

The GovernLayer client is thread-safe. You can share a single instance across threads:

```python
from concurrent.futures import ThreadPoolExecutor

gl = GovernLayer(api_key="gl_your_key")

systems = ["chatbot", "loan-scorer", "fraud-detector"]

with ThreadPoolExecutor(max_workers=3) as pool:
    futures = [
        pool.submit(gl.scan, system_name=s, reasoning_trace="test")
        for s in systems
    ]
    results = [f.result() for f in futures]
```

## License

MIT
