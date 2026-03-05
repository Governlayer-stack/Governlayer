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
  agents/
    orchestrator.py      # LangGraph StateGraph: drift -> risk -> decide -> [escalate] -> ledger
    compliance_agent.py  # ReAct agent for framework scanning
    threat_agent.py      # ReAct agent for MITRE ATLAS / OWASP analysis
  mcp/
    server.py            # FastMCP server with 10 tools (standalone, no auth/db)
  security/
    auth.py              # Password hashing, JWT create/verify
```

Legacy files (`api.py`, `database.py`, `drift_detection.py`, `governlayer_mcp.py`) remain at root for backward compatibility during migration.

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
- **Dual LLM**: `USE_LOCAL_LLM=true` routes to Ollama for sovereign/offline operation.
- **Docker**: Multi-stage build, non-root user, health checks. Compose includes Postgres, Redis, optional Ollama.
- **Migrations**: Alembic configured, models auto-detected from `src.models.database.Base`.
- **Testing**: pytest with FastAPI TestClient fixtures in `tests/conftest.py`.
