# GovernLayer GitHub Action

Run AI governance compliance checks (behavioral drift detection, 6-dimension risk scoring, policy enforcement) on every pull request and deployment via the GovernLayer API.

## What It Does

On every PR, this action:

1. **Scans** your AI system for behavioral drift and risk factors via `/v1/scan`
2. **Scores** risk across 6 dimensions (privacy, autonomy, infrastructure, oversight, transparency, fairness) via `/v1/risk`
3. **Posts** a detailed governance report as a PR comment
4. **Fails** the check if the risk score falls below your configured threshold

## Prerequisites

- A GovernLayer API key (`gl_xxx`). Get one at [governlayer.ai](https://governlayer.ai) or via the `/enterprise/api-keys` endpoint.
- Store the API key as a GitHub repository secret named `GOVERNLAYER_API_KEY`.

## Quick Start

Add this to `.github/workflows/governance.yml` in your repository:

```yaml
name: AI Governance Check

on:
  pull_request:
    branches: [main]

permissions:
  pull-requests: write

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: GovernLayer Governance Check
        uses: Governlayer-stack/Governlayer/integrations/github-action@main
        with:
          api_key: ${{ secrets.GOVERNLAYER_API_KEY }}
          system_name: "my-ai-service"
```

## Full Example

```yaml
name: AI Governance Check

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

permissions:
  pull-requests: write

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: GovernLayer Governance Check
        id: govern
        uses: Governlayer-stack/Governlayer/integrations/github-action@main
        with:
          api_key: ${{ secrets.GOVERNLAYER_API_KEY }}
          system_name: "recommendation-engine"
          reasoning_trace: "User preference model updated with new training data"
          use_case: "content_recommendation"
          handles_personal_data: "true"
          makes_autonomous_decisions: "false"
          used_in_critical_infrastructure: "false"
          has_human_oversight: "true"
          is_explainable: "true"
          has_bias_testing: "true"
          fail_on_high_risk: "true"
          risk_threshold: "50"

      - name: Use governance outputs
        if: always()
        run: |
          echo "Decision: ${{ steps.govern.outputs.action }}"
          echo "Risk Score: ${{ steps.govern.outputs.risk_score }}"
          echo "Risk Level: ${{ steps.govern.outputs.risk_level }}"
          echo "Drift: ${{ steps.govern.outputs.drift_coefficient }}"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api_url` | No | `https://www.governlayer.ai` | GovernLayer API base URL |
| `api_key` | **Yes** | -- | GovernLayer API key (`gl_xxx`). Use a GitHub secret. |
| `system_name` | **Yes** | -- | Name of the AI system being governed |
| `reasoning_trace` | No | `Automated CI/CD governance scan...` | Reasoning trace to analyze for behavioral drift |
| `use_case` | No | `general` | Use case category for drift manifold selection |
| `handles_personal_data` | No | `false` | System handles PII/personal data |
| `makes_autonomous_decisions` | No | `false` | System makes decisions without human approval |
| `used_in_critical_infrastructure` | No | `false` | System is deployed in critical infrastructure |
| `has_human_oversight` | No | `true` | System has human oversight mechanisms |
| `is_explainable` | No | `true` | System decisions are explainable |
| `has_bias_testing` | No | `false` | System has undergone bias testing |
| `fail_on_high_risk` | No | `true` | Fail the workflow if risk exceeds threshold |
| `risk_threshold` | No | `50` | Risk score threshold (scores below this value fail) |
| `post_comment` | No | `true` | Post governance report as a PR comment |

## Outputs

| Output | Description |
|--------|-------------|
| `action` | Governance decision: `APPROVE`, `ESCALATE_HUMAN`, or `BLOCK` |
| `risk_score` | Overall risk score (0-100, higher is safer) |
| `risk_level` | Risk level: `LOW`, `MEDIUM`, or `HIGH` |
| `drift_coefficient` | Behavioral drift coefficient (0.0-1.0) |
| `vetoed` | Whether the system was vetoed due to drift (`true`/`false`) |

## Risk Scoring

GovernLayer scores risk across 6 dimensions. Each dimension is scored 0-100, and the overall score is the average. **Higher scores are safer.**

| Dimension | Safe (100) | At Risk |
|-----------|-----------|---------|
| **Privacy** | No personal data handled | Handles PII (40) |
| **Autonomy** | No autonomous decisions | Makes autonomous decisions (30) |
| **Infrastructure** | Not in critical systems | Critical infrastructure (25) |
| **Oversight** | Human oversight present | No human oversight (20) |
| **Transparency** | Explainable decisions | Not explainable (30) |
| **Fairness** | Bias testing done | No bias testing (25) |

### Risk Levels

- **LOW** (score >= 80): System is within safe governance boundaries
- **MEDIUM** (score 50-79): Some risk factors present; review recommended
- **HIGH** (score < 50): Significant risk; human review or blocking required

### Governance Decisions

- **APPROVE**: System passes all checks
- **ESCALATE_HUMAN**: Risk or drift warrants human review
- **BLOCK**: Behavioral drift detected or critical risk threshold exceeded

## Threshold Configuration

The `risk_threshold` input sets the minimum acceptable risk score. Since higher scores mean lower risk:

- `risk_threshold: 80` -- Strict. Only LOW-risk systems pass.
- `risk_threshold: 50` -- Moderate (default). HIGH-risk systems fail.
- `risk_threshold: 30` -- Permissive. Only the riskiest configurations fail.

Set `fail_on_high_risk: false` to report results without failing the workflow.

## Self-Hosted API

If you run your own GovernLayer instance, point the action at it:

```yaml
- uses: Governlayer-stack/Governlayer/integrations/github-action@main
  with:
    api_url: "https://governlayer.internal.company.com"
    api_key: ${{ secrets.GOVERNLAYER_API_KEY }}
    system_name: "my-system"
```

## Multi-System Governance

Run checks for multiple AI systems in the same workflow:

```yaml
jobs:
  governance:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        system:
          - name: "recommendation-engine"
            personal_data: "true"
            autonomous: "false"
          - name: "fraud-detector"
            personal_data: "true"
            autonomous: "true"
          - name: "content-moderator"
            personal_data: "false"
            autonomous: "true"
    steps:
      - uses: actions/checkout@v4
      - uses: Governlayer-stack/Governlayer/integrations/github-action@main
        with:
          api_key: ${{ secrets.GOVERNLAYER_API_KEY }}
          system_name: ${{ matrix.system.name }}
          handles_personal_data: ${{ matrix.system.personal_data }}
          makes_autonomous_decisions: ${{ matrix.system.autonomous }}
```

## Deploy Gate

Block deployments that fail governance checks:

```yaml
name: Deploy with Governance Gate

on:
  push:
    branches: [main]

jobs:
  governance:
    runs-on: ubuntu-latest
    outputs:
      action: ${{ steps.check.outputs.action }}
    steps:
      - uses: actions/checkout@v4
      - id: check
        uses: Governlayer-stack/Governlayer/integrations/github-action@main
        with:
          api_key: ${{ secrets.GOVERNLAYER_API_KEY }}
          system_name: "production-ai"
          fail_on_high_risk: "true"
          risk_threshold: "70"

  deploy:
    needs: governance
    if: needs.governance.outputs.action == 'APPROVE'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Deploying..."
```

## Troubleshooting

### Action fails with HTTP 401/403

Your API key is invalid or missing required scopes. Ensure the key has `scan` and `risk` scopes. Regenerate at `/enterprise/api-keys` if needed.

### Action fails with HTTP 422

The request body is malformed. Check that `system_name` is provided and non-empty.

### PR comment not posted

- Ensure the workflow has `permissions: pull-requests: write`
- Comments are only posted on `pull_request` and `pull_request_target` events
- The `GITHUB_TOKEN` must have write access to the repository

### Risk score seems wrong

Risk scoring is deterministic based on the boolean inputs. Double-check that your `handles_personal_data`, `makes_autonomous_decisions`, etc. values accurately reflect your system.

## License

MIT -- see the [GovernLayer repository](https://github.com/Governlayer-stack/Governlayer) for details.
