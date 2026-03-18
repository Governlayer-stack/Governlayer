# Statement of Work (SOW)
## GovernLayer — The Governance Layer for Agentic AI

**Document Version:** 1.0
**Date:** March 17, 2026
**Prepared by:** GovernLayer Engineering
**Client/Stakeholder:** Enterprise AI Teams, Compliance Officers, CISOs

---

## 1. Executive Summary

GovernLayer is an autonomous AI governance platform that provides real-time compliance auditing, behavioral drift detection, multi-dimensional risk scoring, agent registry and shadow AI discovery, policy enforcement, and an immutable hash-chained audit ledger. The platform is designed for enterprises deploying AI systems at scale who need to meet regulatory requirements across 27 frameworks and 18 jurisdictions.

The platform is delivered as a REST API (FastAPI), an MCP server (FastMCP), and a web dashboard, with multi-LLM orchestration via the Achonye architecture.

---

## 2. Platform Scope

### 2.1 Deliverables Summary

| Category | Count | Description |
|----------|-------|-------------|
| API Endpoints | 126 | Full REST API with OpenAPI documentation |
| Regulatory Frameworks | 27 | Monitored compliance frameworks |
| Report Generators | 18 | Full regulatory compliance reports |
| LLM Models | 14 | Multi-provider orchestration (local + cloud) |
| Consensus Strategies | 3 | Voting, Chain-of-Verification, Adversarial Debate |
| Automated Tests | 127 | Comprehensive test suite |
| Source Files | 72 | ~11,000 lines of production code |
| Test Files | 15 | ~1,900 lines of test code |

---

## 3. Functional Deliverables

### 3.1 Core Governance Engine

| Feature | Endpoint(s) | Description |
|---------|-------------|-------------|
| Governance Decision | `POST /govern`, `POST /v1/govern` | Drift analysis + risk scoring + decision (APPROVE/BLOCK/ESCALATE) |
| Drift Detection | `POST /drift`, `POST /v1/drift` | Sentence-transformer embeddings vs safety manifolds, drift coefficient calculation |
| Risk Scoring | `POST /risk-score`, `POST /v1/risk` | 6-dimension deterministic scoring (Privacy, Autonomy, Infrastructure, Oversight, Transparency, Fairness) |
| Quick Scan | `POST /v1/scan` | Deterministic scan — no LLM, instant results |
| Full Pipeline | `POST /automate/full-pipeline` | Drift → Risk → Decision → Audit → Ledger in one call |

### 3.2 Audit & Compliance

| Feature | Endpoint(s) | Description |
|---------|-------------|-------------|
| LLM Compliance Audit | `POST /audit`, `POST /v1/audit/{system}` | Multi-framework LLM-powered compliance audit |
| Audit History | `GET /audit-history` | Paginated audit trail |
| Immutable Ledger | `GET /ledger` | SHA-256 hash-chained audit records |
| Mutation Log | `GET /v1/enterprise/audit-log` | Who changed what, when, with filters |
| Compliance Reports | `POST /v1/reports` | Full regulatory report generation (18 frameworks) |
| Compliance Summary | `GET /v1/reports/compliance-summary` | Live compliance scores across key frameworks |

### 3.3 Regulatory Report Generation (18 Frameworks)

| Framework | Jurisdiction | Industry Focus |
|-----------|-------------|----------------|
| EU AI Act | European Union | All |
| NIST AI RMF | United States | All |
| ISO 42001 | International | All |
| ISO/IEC 27001:2022 | International | All |
| NIS2 Directive | European Union | Essential/Important entities |
| DORA | European Union | Finance, Banking, Insurance |
| GDPR | European Union | All |
| CCPA/CPRA | California, USA | All |
| HIPAA | United States | Healthcare, Pharma |
| SOC 2 Type II | United States | All |
| NIST CSF 2.0 | United States | All |
| MITRE ATLAS | International | All |
| OWASP AI Top 10 | International | All |
| OECD AI Principles | International (46 countries) | All |
| IEEE Ethically Aligned Design | International | All |
| HITRUST AI Assurance | United States | Healthcare |
| NYC Local Law 144 | New York City | Employment, HR Tech |
| Colorado SB 21-169 | Colorado | Insurance |

### 3.4 AI Agent Registry & Shadow AI Discovery

| Feature | Endpoint(s) | Description |
|---------|-------------|-------------|
| Agent Registration | `POST /v1/agents` | Register AI agents with type, owner, tools, autonomy level |
| Agent Listing | `GET /v1/agents` | Paginated list with filters (team, status, shadow) |
| Agent Governance | `POST /v1/agents/{id}/governance` | Approve, reject, or suspend agents |
| Shadow AI Scan | `POST /v1/agents/discovery/scan` | Detect unregistered AI usage via API traffic patterns |

### 3.5 Model Registry & Lifecycle

| Feature | Endpoint(s) | Description |
|---------|-------------|-------------|
| Model Registration | `POST /v1/models` | Register AI models with metadata and risk tier |
| Model Lifecycle | `PUT /v1/models/{id}/lifecycle` | Development → Staging → Production → Retired |
| Model Cards | `POST /v1/models/{id}/card` | Intended use, limitations, fairness analysis, evaluation metrics |
| Model Listing | `GET /v1/models` | Paginated with governance status filters |

### 3.6 Incident Management

| Feature | Endpoint(s) | Description |
|---------|-------------|-------------|
| Create Incident | `POST /v1/incidents` | Report AI governance incidents with severity |
| Update Incident | `PATCH /v1/incidents/{id}` | Status transitions, assignment, resolution |
| List/Filter | `GET /v1/incidents` | Paginated with severity and status filters |
| Webhook Events | Automatic | Fires `incident.created`, `incident.updated`, `incident.resolved` |

### 3.7 Policy Engine

| Feature | Endpoint(s) | Description |
|---------|-------------|-------------|
| Create Policy | `POST /v1/policies` | Define governance rules with conditions and actions |
| Evaluate Policy | `POST /v1/policies/{id}/evaluate` | Test a system against policy rules |
| Policy CRUD | `GET/PUT/DELETE /v1/policies` | Full lifecycle management |

### 3.8 Threat Analysis

| Feature | Endpoint(s) | Description |
|---------|-------------|-------------|
| Threat Assessment | `POST /threats` | MITRE ATLAS + OWASP AI threat analysis |
| Incident Response | `POST /incident-response` | Response plan generation |
| Jurisdiction Analysis | `POST /jurisdiction` | Multi-country regulatory mapping |
| Compliance Deadlines | `POST /deadlines` | Regulatory deadline tracking |

---

## 4. Enterprise Features

### 4.1 Multi-Tenancy & API Keys

| Feature | Description |
|---------|-------------|
| Organizations | Create and manage orgs with plan tiers (free, starter, pro, enterprise) |
| API Key Provisioning | Self-service key generation with `gl_` prefix, scoped permissions |
| Dual Authentication | API keys (`Bearer gl_xxx`) and JWT tokens side-by-side |
| RBAC Scopes | `govern`, `audit`, `risk`, `scan` — per-key scope enforcement |
| API Key Rotation | Revoke and regenerate keys without downtime |

### 4.2 Rate Limiting & Usage Quotas

| Plan | Requests/Minute | Requests/Month |
|------|----------------|----------------|
| Free | 20 | 500 |
| Starter ($49/mo) | 100 | 10,000 |
| Pro ($199/mo) | 500 | 100,000 |
| Enterprise (custom) | 2,000 | Unlimited |

- Redis-backed sliding window rate limiting (in-memory fallback)
- Monthly usage quota enforcement with 60s cached DB lookups
- `X-RateLimit-*` and `X-Monthly-*` response headers

### 4.3 Webhooks

| Feature | Description |
|---------|-------------|
| Webhook Registration | Subscribe to events per organization |
| HMAC-SHA256 Signatures | Cryptographic verification of webhook payloads |
| Event Types | `governance.approve`, `governance.block`, `governance.escalate_human`, `incident.created`, `incident.updated`, `incident.resolved` |

### 4.4 Billing (Stripe Integration)

| Feature | Endpoint | Description |
|---------|----------|-------------|
| Checkout | `POST /billing/checkout` | Create Stripe Checkout session for plan upgrade |
| Webhook Handler | `POST /billing/webhook` | Process subscription events (upgrade, cancel, payment failure) |
| Customer Portal | `GET /billing/portal/{slug}` | Redirect to Stripe self-service portal |
| Usage Summary | `GET /billing/usage/{slug}` | Current month usage with cap and percentage |

### 4.5 Email Notifications

| Template | Trigger | Description |
|----------|---------|-------------|
| Welcome | User registration | Onboarding with quick-start guide |
| Password Reset | Forgot password | Branded email with secure token link |
| Incident Alert | High/critical incident created | Severity-colored alert to reporter |
| Webhook Failure | Delivery failure | URL and status code details |

Supports **Resend** (primary), **SMTP** (fallback), and **dev-mode logging**.

### 4.6 Multi-Factor Authentication (TOTP)

| Feature | Endpoint | Description |
|---------|----------|-------------|
| Setup | `POST /auth/mfa/setup` | Generate TOTP secret, QR code, 10 backup codes |
| Verify & Enable | `POST /auth/mfa/verify` | Validate authenticator code, activate MFA |
| Disable | `POST /auth/mfa/disable` | Disable via TOTP or backup code |
| Status | `GET /auth/mfa/status` | Check if MFA is enabled |
| Login Integration | `POST /auth/login` | Requires `mfa_code` field when MFA is active |

Compatible with Google Authenticator, Authy, 1Password, and any TOTP app.

---

## 5. Analytics & Observability

### 5.1 API Usage Analytics

| Endpoint | Description |
|----------|-------------|
| `GET /v1/analytics/usage/summary` | Total requests, error rate, avg latency, active keys |
| `GET /v1/analytics/usage/trends` | Time series (hour/day/week granularity) |
| `GET /v1/analytics/usage/top-endpoints` | Most-used endpoints ranked |
| `GET /v1/analytics/usage/latency` | p50, p95, p99 percentile latencies |
| `GET /v1/analytics/usage/errors` | Error breakdown by status code |
| `GET /v1/analytics/usage/governance` | Approve/block/escalate decision breakdown |

### 5.2 Organization Dashboard

| Endpoint | Description |
|----------|-------------|
| `GET /v1/dashboard` | Full environment healthcheck (JSON) — models, incidents, policies, health score |
| `GET /dashboard` | Interactive web dashboard (HTML) with live data |

Dashboard includes: health score, model registry, incident tracker, compliance bars (live from report generators), agent registry, shadow AI scanner, policy management.

---

## 6. AI/LLM Architecture (Achonye)

### 6.1 Multi-LLM Orchestration

| Layer | Role | Models |
|-------|------|--------|
| Leader | Strategic decisions, task routing | Claude Opus |
| Board | Parallel analysis, diverse perspectives | Claude Sonnet, Gemini Pro, GPT-4o |
| Validator | Consensus verification | 3-strategy engine |
| Operators | Task execution | 14 models across 3 providers |

### 6.2 Model Providers

| Provider | Models | Use Case |
|----------|--------|----------|
| Ollama (local) | Llama 3 8B, Mistral 7B, DeepSeek-R1, Qwen 2.5, Phi-3 Mini | Privacy-sensitive, zero-cost tasks |
| Groq (fast cloud) | Llama 3.3 70B | Speed-critical cloud tasks |
| OpenRouter (universal) | Gemini 2.5, GPT-4o, Grok, DeepSeek V3, Kimi, Devstral, Claude Sonnet, Claude Opus | Complex/premium tasks |

### 6.3 Consensus Strategies

| Strategy | Description |
|----------|-------------|
| Voting | 3+ models must agree on the answer |
| Chain-of-Verification | Generate → Question → Verify → Synthesize |
| Adversarial Debate | Claim → Critique → Judge |

### 6.4 Intelligent Task Router

Routes tasks by complexity and capability analysis:
- **Trivial** → Local Ollama (free)
- **Simple** → Groq or local
- **Complex** → Cloud via OpenRouter
- **Critical** → Multi-LLM consensus

---

## 7. Infrastructure

### 7.1 Technology Stack

| Component | Technology |
|-----------|-----------|
| API Framework | FastAPI (Python 3.11) |
| Database | PostgreSQL 15 |
| Cache/Queue | Redis |
| ORM | SQLAlchemy 2.x |
| Migrations | Alembic |
| Auth | JWT (jose) + bcrypt + TOTP (pyotp) |
| MCP Server | FastMCP (12 tools) |
| Agent Orchestration | LangGraph StateGraph |
| Deployment | Railway (Docker, multi-stage build) |
| CI/CD | GitHub Actions (lint + test on every push/PR) |
| Linting | Ruff |

### 7.2 Security

| Measure | Implementation |
|---------|---------------|
| CORS | Locked to `governlayer.ai` origins |
| HSTS | 2-year max-age, includeSubDomains, preload |
| Security Headers | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy |
| Password Security | bcrypt, min 8 chars, uppercase+lowercase+digit required |
| API Key Hashing | SHA-256 (raw keys never stored) |
| Webhook Signatures | HMAC-SHA256 |
| MFA | TOTP with hashed backup codes |
| Rate Limiting | Per-minute + monthly quotas |

### 7.3 Database Schema

| Table | Purpose |
|-------|---------|
| `users` | User accounts with MFA and password reset |
| `audit_records` | Hash-chained governance decisions |
| `risk_scores` | Risk scoring history |
| `mutation_logs` | Who changed what, when |
| `organizations` | Multi-tenant orgs with Stripe billing |
| `api_keys` | Scoped API keys with rate limits |
| `usage_records` | Per-request usage metering |
| `webhooks` | Event subscriptions per org |
| `registered_models` | AI model registry |
| `model_cards` | Model documentation |
| `incidents` | Incident lifecycle tracking |
| `ai_agents` | Agent registry |
| `governance_policies` | Rule-based policy engine |

### 7.4 Deployment

| Environment | Details |
|-------------|---------|
| Production | Railway (perpetual-abundance project) |
| Database | Railway managed PostgreSQL |
| Docker | Multi-stage build, non-root user, health checks |
| Auto-migration | `alembic upgrade head` before server start |
| Health Check | `GET /health` (DB connectivity + version) |

---

## 8. Automation & Integration

| Feature | Description |
|---------|-------------|
| Autonomous Daemon | `scripts/governlayer_daemon.py` — runs full pipeline on schedule |
| n8n Workflows | Importable JSON workflow for hourly governance scans |
| MCP Server | 12 tools for Claude Desktop / IDE integration |
| Webhook System | Real-time event push to external systems |
| Bot Accounts | `POST /automate/register-bot` for service-to-service auth |

---

## 9. Testing

| Suite | Tests | Coverage |
|-------|-------|----------|
| Core API | 16 | Auth, health, frameworks, dashboard, security headers |
| Governance | 8 | Drift detection, risk scoring |
| Enterprise | 9 | Orgs, API keys, scopes, webhooks |
| Model Registry | 15 | CRUD, lifecycle, model cards |
| Incidents | 14 | CRUD, status transitions, webhook events |
| Agent Registry | 17 | CRUD, governance actions, shadow AI scan |
| Reports | 12 | 18 frameworks, compliance summary |
| Billing | 6 | Monthly caps, usage endpoint |
| MFA | 6 | Setup, verify, disable, backup codes |
| Notifications | 5 | Dev-mode send, all 4 templates |
| Analytics | 8 | All 6 usage analytics endpoints |
| Ledger | 4 | Hash determinism, chain integrity |
| Risk | 2 | Low/high risk scoring |
| **Total** | **127** | |

CI runs automatically on every push and pull request via GitHub Actions.

---

## 10. Acceptance Criteria

- [ ] All 127 automated tests pass
- [ ] API responds at production URL with valid health check
- [ ] Governance decisions produce hash-chained audit records
- [ ] Drift detection correctly flags behavioral anomalies
- [ ] Risk scoring produces consistent, deterministic results
- [ ] All 18 report generators produce valid compliance reports
- [ ] Rate limiting enforces per-minute and monthly quotas
- [ ] API keys are properly scoped and revocable
- [ ] MFA setup/verify/disable lifecycle works with standard TOTP apps
- [ ] Webhooks fire with valid HMAC-SHA256 signatures
- [ ] Dashboard displays live data from all API endpoints
- [ ] CI/CD pipeline runs on every push and PR

---

## 11. Pricing Structure

| Plan | Monthly Price | Rate Limit | Monthly Quota | Features |
|------|-------------|------------|---------------|----------|
| Free | $0 | 20 req/min | 500 req/mo | Core governance, 1 org, 1 API key |
| Starter | $49 | 100 req/min | 10,000 req/mo | + Reports, analytics, webhooks |
| Pro | $199 | 500 req/min | 100,000 req/mo | + Multi-LLM consensus, priority support |
| Enterprise | Custom | 2,000 req/min | Unlimited | + SSO, dedicated support, SLA |

---

*GovernLayer — The Governance Layer for Agentic AI*
*Built for enterprises that need to govern AI at scale.*
