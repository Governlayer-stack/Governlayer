# GovernLayer Architecture

## System Overview

```
                          +------------------+
                          |   Client / CI    |
                          |  (API / GitHub   |
                          |   Action / MCP)  |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |   FastAPI Router  |
                          |   (src/main.py)   |
                          +--------+---------+
                                   |
              +--------------------+--------------------+
              |                    |                    |
     +--------v-------+  +--------v-------+  +--------v-------+
     | Drift Detection |  | Risk Scoring   |  | LLM Consensus  |
     | (embeddings)    |  | (deterministic)|  | (multi-model)  |
     +--------+-------+  +--------+-------+  +--------+-------+
              |                    |                    |
              +--------------------+--------------------+
                                   |
                          +--------v---------+
                          |  Agent Orchestr.  |
                          |  (LangGraph)      |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |  Audit Ledger     |
                          |  (SHA-256 chain)  |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |   PostgreSQL      |
                          +------------------+
```

## Components

### API Layer (`src/api/`)

- **auth.py** -- JWT registration, login, password reset
- **governance.py** -- `/govern` endpoint: full pipeline (drift + risk + decide + ledger)
- **audit.py** -- `/audit` LLM-powered compliance audits
- **risk.py** -- `/risk-score` deterministic 6-dimension scoring
- **ledger.py** -- `/ledger` hash-chained audit trail queries
- **threats.py** -- `/threats` MITRE ATLAS and OWASP AI analysis
- **automation.py** -- `/automate/*` bot accounts and pipeline triggers
- **enterprise.py** -- `/v1/enterprise/*` org management, API keys, usage
- **v1.py** -- Versioned enterprise endpoints with API key auth
- **achonye.py** -- `/achonye/*` multi-LLM orchestration endpoints

### Drift Detection (`src/drift/detection.py`)

Monitors behavioral drift in AI systems using sentence-transformer embeddings. Computes cosine distance between current behavior and safety manifolds. Gracefully degrades to keyword-only mode when embeddings are unavailable.

### Risk Scoring (`src/api/risk.py`)

Deterministic scoring across 6 dimensions. No LLM involved:

| Dimension | High Score (Safe) | Low Score (Risky) |
|---|---|---|
| Privacy | No personal data (100) | Handles personal data (40) |
| Autonomy Risk | No autonomous decisions (100) | Makes autonomous decisions (30) |
| Infrastructure Risk | Not critical infra (100) | Critical infrastructure (25) |
| Oversight | Human oversight (100) | No oversight (20) |
| Transparency | Explainable (100) | Not explainable (30) |
| Fairness | Bias tested (100) | No bias testing (25) |

### Achonye Multi-LLM Architecture (`src/llm/`, `src/agents/achonye.py`)

Hierarchical orchestration across 14 models:

```
Leader: Claude Opus (strategic decisions)
  |
Board: Claude Sonnet, Gemini Pro, GPT-4o (complex tasks)
  |
Validator: Consensus Engine (hallucination resistance)
  |
Operators: 14 models across Ollama, Groq, OpenRouter
```

**Router** (`src/llm/router.py`): Analyzes task complexity and capability requirements, routes to optimal model. Trivial tasks go to local Ollama (zero cost), critical tasks go through multi-model consensus.

**Consensus Engine** (`src/llm/consensus.py`): Three strategies:
1. **Voting** -- 3+ models must agree
2. **Chain-of-Verification** -- generate, question, verify, synthesize
3. **Adversarial Debate** -- claim, critique, judge

### Agent Orchestration (`src/agents/orchestrator.py`)

LangGraph StateGraph with conditional edges:

```
drift_check -> risk_score -> decide -> [escalate?] -> record_ledger
```

Human-in-the-loop escalation gate triggers when risk exceeds configurable threshold.

### Audit Ledger (`src/models/database.py`)

SHA-256 hash-chained immutable audit trail:

- Genesis hash: `SHA256("GOVERNLAYER_GENESIS")`
- Each record: `current_hash = SHA256(previous_hash + action + system_name + timestamp)`
- Chain integrity verifiable at any time
- Tamper-evident: breaking one hash invalidates all subsequent records

### Compliance Frameworks

29 frameworks supported:

NIST AI RMF, EU AI Act, ISO 42001, ISO 27001, NIS2, DORA, MITRE ATLAS, OWASP AI, SOC 2, GDPR, CCPA, HIPAA, IEEE Ethics, OECD AI, NIST CSF, UNESCO AI, Singapore AI, UK AI, Canada AIDA, China AI, COBIT, ITIL, Zero Trust, CIS Controls, FAIR Risk, CSA AI, US EO AI, DSA, DMA

## Data Flow

```
Request -> Authentication (JWT / API Key)
       -> Rate Limiting (Redis, plan-based)
       -> Drift Detection (embedding similarity)
       -> Risk Scoring (6 dimensions)
       -> Decision Engine (approve / flag / escalate / block)
       -> [Escalation Gate if high risk]
       -> Audit Ledger (hash-chained record)
       -> Response + Webhook dispatch
```

## Infrastructure

- **Runtime:** Python 3.11, FastAPI, Uvicorn
- **Database:** PostgreSQL 15
- **Cache:** Redis (rate limiting, sessions)
- **Local LLM:** Ollama (Llama 3, Mistral, DeepSeek-R1, Qwen, Phi)
- **Cloud LLM:** Groq (fast), OpenRouter (500+ models)
- **Deployment:** Railway (Docker, managed Postgres)
- **CI/CD:** GitHub Actions (lint + test on push/PR)
