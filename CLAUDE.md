# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GovernLayer is an autonomous AI governance platform providing compliance auditing, behavioral drift detection, risk scoring, agent orchestration, and an immutable hash-chained audit ledger. Two interfaces: REST API (FastAPI) and MCP server (FastMCP). Agents are orchestrated via LangGraph.

## Commands

```bash
make dev              # Run API server with hot reload (port 8000)
make test             # Run all tests
make test-drift       # Run drift detection tests only
make test-one TEST=tests/test_drift.py::test_name  # Single test
make lint             # Ruff linting
make format           # Auto-format
make mcp              # Run MCP server (stdio)
make setup            # Full local setup (venv + deps + db)
make docker-up        # Start full stack (API + Postgres + Redis)
make docker-down      # Stop containers
make docker-local-llm # Start stack with Ollama for local inference
make db-init          # Initialize database tables
make db-migrate       # Run Alembic migrations
make db-revision MSG="description"  # Create new migration
make ollama-pull      # Pull default local models
make n8n-start        # Start n8n workflow automation service
make n8n-stop         # Stop n8n service
make n8n-status       # Check n8n health
make n8n-logs         # Tail n8n logs
make n8n-ui           # Open n8n UI in browser
make daemon-run       # Run governance pipeline once (immediate)
make daemon-start     # Start autonomous daemon (hourly)
make daemon-stop      # Stop autonomous daemon
make daemon-health    # Check all service health
```

## Architecture

```
src/
  config.py              # Centralized settings from env (pydantic-settings)
  main.py                # FastAPI app factory, router registration
  api/
    auth.py              # JWT registration + login
    governance.py        # /govern — drift + risk + decide + ledger (main pipeline)
    audit.py             # /audit, /audit-history — LLM compliance audits
    risk.py              # /risk-score — 6-dimension deterministic scoring
    ledger.py            # /ledger — hash-chained audit trail
    threats.py           # /threats, /incident-response, /jurisdiction, /deadlines
    deps.py              # Shared: LLM client, search tool singletons
  models/
    database.py          # SQLAlchemy models (AuditRecord, RiskScoreRecord, User), hash chain
    schemas.py           # Pydantic request/response models
  drift/
    detection.py         # Sentence-transformer embeddings vs safety manifolds, D_c calculation
  llm/
    providers.py         # 14-model registry: Ollama, Groq, OpenRouter (Gemini, GPT, Grok, etc.)
    router.py            # Intelligent task router: complexity + capability -> optimal model
    consensus.py         # Multi-LLM consensus: Voting, Chain-of-Verification, Adversarial Debate
  agents/
    achonye.py           # THE LEADER: hierarchical multi-LLM orchestrator (Leader->Board->Validator->Operators)
    orchestrator.py      # LangGraph StateGraph: drift -> risk -> decide -> [escalate] -> ledger
    compliance_agent.py  # ReAct agent for framework scanning
    threat_agent.py      # ReAct agent for MITRE ATLAS / OWASP analysis
  mcp/
    server.py            # FastMCP server with 12 tools (standalone, no auth/db)
  security/
    auth.py              # Password hashing, JWT create/verify
scripts/
  governlayer_daemon.py  # Autonomous scheduler — runs full pipeline on cron
n8n-workflows/
  governlayer_full_pipeline.json  # Importable n8n workflow (hourly governance)
```

Legacy root files (`api.py`, `database.py`, `drift_detection.py`, `governlayer_mcp.py`) have been removed. All code lives under `src/`.

## Environment

- Python 3.11 (`/opt/homebrew/bin/python3.11`)
- PostgreSQL 15 (local via homebrew, Docker via compose)
- Redis (cache + message broker)
- Ollama (local model inference, optional via `--profile local-llm`)
- `GROQ_API_KEY` in `.env` for cloud LLM
- See `.env.example` for all config variables

## Key Technical Details

- **Config**: All settings centralized in `src/config.py` via pydantic-settings. No hardcoded secrets.
- **Audit ledger**: Hash-chained via SHA-256. Genesis hash = `SHA256("GOVERNLAYER_GENESIS")`. Each record stores `previous_hash` + `current_hash`.
- **Risk scoring**: Deterministic (not LLM). Boolean inputs -> fixed scores across 6 dimensions.
- **Drift detection**: Gracefully degrades — full embedding mode when sentence-transformers available, keyword-only fallback otherwise.
- **Agent orchestration**: LangGraph StateGraph with conditional edges for human-in-the-loop escalation.
- **Achonye Architecture**: Multi-LLM orchestration — Leader (Claude Opus) -> Board (Sonnet, Gemini, GPT-4o) -> Validator (consensus engine) -> Operators (14 models across local + cloud). Routes trivial tasks to local Ollama (zero cost), critical tasks through multi-LLM consensus.
- **OpenRouter**: Universal gateway for cloud models (one API key, 500+ models). All non-Groq, non-Ollama models route through OpenRouter.
- **Consensus Engine**: Three hallucination-resistance strategies — Voting (3+ models agree), Chain-of-Verification (generate->question->verify->synthesize), Adversarial Debate (claim->critique->judge).
- **Docker**: Multi-stage build, non-root user, health checks. Compose includes Postgres, Redis, optional Ollama.
- **Migrations**: Alembic configured, models auto-detected from `src.models.database.Base`.
- **Testing**: pytest with FastAPI TestClient fixtures in `tests/conftest.py`.
- **n8n Integration**: Workflow automation on port 5678, runs as launchd service. SSH to localhost enables n8n->Claude Code execution. Helper script at `~/.npm-global/bin/n8n-claude`.
- **Automation API**: `/automate/full-pipeline` runs drift+risk+audit+ledger in one call. `/automate/scan` for instant deterministic checks. `/automate/health` for full service health. `/automate/register-bot` creates service accounts.
- **Autonomous Daemon**: `scripts/governlayer_daemon.py` — standalone scheduler that runs the full pipeline on all monitored systems. Can run once or loop. launchd plist at `com.governlayer.daemon`.
- **n8n Workflows**: Importable JSON at `n8n-workflows/governlayer_full_pipeline.json` — hourly scheduled pipeline with alerting.
