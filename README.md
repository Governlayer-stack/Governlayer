# GovernLayer

**Autonomous AI Governance Platform**

GovernLayer provides real-time compliance, security, and risk management infrastructure for enterprises deploying AI agents. It continuously monitors AI systems for behavioral drift, policy violations, bias, and security vulnerabilities — then enforces governance decisions through an immutable audit ledger.

Built for the agentic AI era, where autonomous systems make decisions at machine speed and traditional compliance frameworks can't keep up.

---

## What It Does

| Capability | Description |
|---|---|
| **Policy Enforcement** | Define governance policies and automatically enforce them across AI agent fleets |
| **Behavioral Drift Detection** | Sentence-transformer embeddings measure semantic drift from safety baselines in real time |
| **Risk Scoring** | Deterministic 6-dimension risk assessment (no LLM dependency for scoring) |
| **Compliance Auditing** | LLM-powered audits against EU AI Act, NIST AI RMF, ISO 42001, SOC 2, GDPR |
| **Bias Detection** | Stereotype, toxicity, sentiment disparity, and disparate impact analysis (EEOC four-fifths rule) |
| **IPI Scanning** | Indirect Prompt Injection vulnerability detection across 6 attack categories |
| **Threat Intelligence** | MITRE ATLAS and OWASP ML threat analysis with incident response workflows |
| **Immutable Audit Ledger** | SHA-256 hash-chained records — tamper-evident, cryptographically verifiable |
| **Multi-LLM Consensus** | Achonye orchestration engine: Voting, Chain-of-Verification, Adversarial Debate across 14 models |
| **Vendor Risk Management** | Third-party AI model and API risk assessment frameworks |

---

## Architecture

```
src/
  main.py                  # FastAPI application factory (36 routers, 100+ endpoints)
  config.py                # Centralized settings (pydantic-settings)
  api/                     # 40 API modules
    governance.py           # Core pipeline: drift -> risk -> decide -> ledger
    audit.py                # LLM compliance auditing
    risk.py                 # 6-dimension deterministic risk scoring
    ledger.py               # Hash-chained audit trail
    safety.py               # Bias detection & AI safety endpoints
    ipi.py                  # Indirect Prompt Injection scanning
    threats.py              # MITRE ATLAS / OWASP threat analysis
    achonye.py              # Multi-LLM orchestration endpoints
    automation.py           # Full pipeline automation & bot accounts
    enterprise.py           # Org management, API keys, usage metering
    billing.py              # Stripe integration (checkout, webhooks, portal)
    v1.py                   # Versioned enterprise API
    ...
  agents/
    achonye.py              # Hierarchical multi-LLM orchestrator (Leader -> Board -> Validator -> Operators)
    orchestrator.py         # LangGraph StateGraph with conditional escalation
    compliance_agent.py     # ReAct agent for framework scanning
    threat_agent.py         # ReAct agent for threat analysis
  drift/
    detection.py            # Embedding-based behavioral drift with graceful degradation
  llm/
    providers.py            # 14-model registry (Ollama, Groq, OpenRouter)
    router.py               # Intelligent task routing (complexity + capability analysis)
    consensus.py            # 3 hallucination-resistance strategies
  safety/
    bias_scanner.py         # Deterministic bias, toxicity, disparate impact detection
  models/
    database.py             # SQLAlchemy models, hash-chain integrity
    schemas.py              # Pydantic request/response models
    tenant.py               # Multi-tenancy (orgs, API keys, usage, webhooks)
  security/
    auth.py                 # JWT authentication
    api_key_auth.py         # API key auth with scope-based RBAC
  middleware/
    rate_limit.py           # Redis-backed rate limiting (plan tiers)
    usage.py                # Usage metering per request
  mcp/
    server.py               # FastMCP server (12 tools, standalone)
scripts/
  governlayer_daemon.py     # Autonomous scheduler (cron-based pipeline execution)
```

---

## Compliance Frameworks

GovernLayer maps controls and generates audit-ready evidence for:

- **EU AI Act** — High-risk AI system requirements, transparency obligations, conformity assessments
- **NIST AI RMF** — Govern, Map, Measure, Manage lifecycle functions
- **ISO 42001** — AI Management System (AIMS) certification readiness
- **ISO 27001 / 27017 / 27018** — Information security, cloud security, PII protection
- **SOC 2 Type II** — Trust service criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy)
- **GDPR** — Data protection impact assessments, automated decision-making (Art. 22)
- **EEOC / Title VII** — Disparate impact analysis, four-fifths rule enforcement
- **HIPAA / HITRUST** — Healthcare AI compliance
- **PCI-DSS** — Payment processing security

---

## Multi-LLM Orchestration (Achonye)

GovernLayer's Achonye engine routes tasks across 14 models for cost optimization and hallucination resistance:

**Hierarchy:**
- **Leader** (Claude Opus) — strategic decisions, complex governance analysis
- **Board** (Sonnet, Gemini, GPT-4o) — deliberation on critical findings
- **Validator** — consensus engine applying one of three strategies
- **Operators** (14 models) — task execution across local and cloud inference

**Consensus Strategies:**
1. **Voting** — 3+ models must agree on findings
2. **Chain-of-Verification** — generate, question, verify, synthesize
3. **Adversarial Debate** — claim, critique, judge

**Token Economics:**
- Trivial tasks → local Ollama (zero cost)
- Simple tasks → Groq (fast, cheap)
- Complex tasks → cloud models via OpenRouter
- Critical tasks → multi-model consensus

---

## Deployment

```bash
# Local development
make setup            # Create venv, install deps, init DB
make dev              # Run API server (port 8000)

# Docker
make docker-up        # API + Postgres + Redis
make docker-local-llm # + Ollama for local inference

# Autonomous operation
make daemon-run       # Run governance pipeline once
make daemon-start     # Start hourly autonomous daemon

# Testing
make test             # All tests
make lint             # Ruff linting
```

**Production:** Deployed on Railway with managed PostgreSQL. Dockerfile with multi-stage build, non-root user, health checks.

---

## API

Two interfaces:

1. **REST API** (FastAPI) — 100+ endpoints, JWT + API key auth, OpenAPI docs at `/docs`
2. **MCP Server** (FastMCP) — 12 tools for IDE and agent integration

**Key endpoints:**

```
POST /govern                    # Full pipeline: drift + risk + decide + ledger
POST /audit                     # LLM compliance audit
POST /risk-score                # Deterministic 6-dimension scoring
GET  /ledger                    # Query hash-chained audit trail
POST /safety/bias/scan          # Bias & toxicity detection
POST /safety/bias/scan/content  # Content pre-screening
POST /ipi/scan                  # Prompt injection vulnerability scan
POST /threats                   # MITRE ATLAS threat analysis
POST /achonye/process           # Multi-LLM orchestrated analysis
POST /consensus                 # Multi-model consensus verification
POST /automate/full-pipeline    # Automated pipeline execution
POST /v1/govern                 # Enterprise versioned API
```

---

## Enterprise Features

- **Multi-tenancy** — Organization isolation, per-org API keys
- **API Key Authentication** — Scoped keys (`gl_xxx`) with RBAC (govern, audit, risk, scan)
- **Rate Limiting** — Redis-backed, tiered by plan (Free: 20, Starter: 100, Pro: 500, Enterprise: 2000 rpm)
- **Usage Metering** — Per-request latency tracking and billing
- **Webhooks** — HMAC-SHA256 signed event delivery
- **Stripe Billing** — Checkout, subscription management, usage-based billing portal

---

## Intellectual Property

- **USPTO Provisional Patent** (64/001,213) — Six-component agentic AI governance architecture covering policy enforcement, behavioral drift detection, multi-dimensional risk scoring, consensus verification, and immutable audit ledgers
- **30 claims** including AGI governance addendum

---

## Stack

| Layer | Technology |
|---|---|
| API | FastAPI, Pydantic v2, Uvicorn |
| Database | PostgreSQL 15, SQLAlchemy, Alembic |
| Cache | Redis |
| LLM (local) | Ollama (Llama 3, Mistral, DeepSeek-R1, Qwen, Phi) |
| LLM (cloud) | Groq, OpenRouter (Claude, Gemini, GPT-4o, Grok, DeepSeek) |
| Agents | LangGraph, LangChain |
| Embeddings | sentence-transformers (with graceful degradation) |
| Auth | JWT + API key dual auth, bcrypt |
| Billing | Stripe |
| CI/CD | GitHub Actions |
| Deployment | Railway, Docker |
| Automation | n8n workflows, launchd daemon |

---

## License

Proprietary. All rights reserved.

---

**GovernLayer** — Governance infrastructure for the agentic AI era.
