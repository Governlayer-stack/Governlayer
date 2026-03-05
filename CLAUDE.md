# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GovernLayer is an AI governance platform that provides compliance auditing, behavioral drift detection, risk scoring, and an immutable audit ledger. It has two interfaces: a REST API (FastAPI) and an MCP server (FastMCP).

## Running the Application

```bash
# API server (default port 8000)
uvicorn api:app --host 0.0.0.0 --port 8000

# MCP server (stdio transport)
python governlayer_mcp.py

# Run drift detection tests
python drift_detection.py

# Initialize database tables
python database.py
```

## Environment Requirements

- Python 3.11
- PostgreSQL database at `postgresql://localhost/governlayer` (hardcoded in `database.py`)
- `GROQ_API_KEY` env var for LLM calls (loaded via dotenv)
- `sentence-transformers` model `all-MiniLM-L6-v2` (auto-downloaded on first run)
- Deployed on Railway via Dockerfile (does NOT include sentence-transformers; drift detection unavailable in deployed build)

## Architecture

**`api.py`** — FastAPI REST API. All endpoints require JWT auth (`/auth/register`, `/auth/login` to get tokens). Core endpoints:
- `/govern` — The main decision controller: runs drift detection + risk scoring, then APPROVE/ESCALATE/BLOCK. Records to immutable audit ledger.
- `/audit` — LLM-based compliance audit against governance frameworks.
- `/drift` — Standalone drift detection endpoint.
- `/risk-score` — 6-dimension risk scoring (Privacy, Autonomy, Infrastructure, Oversight, Transparency, Fairness).
- `/ledger`, `/audit-history` — Query the hash-chained audit ledger.
- `/threats`, `/incident-response`, `/jurisdiction`, `/deadlines` — LLM+search-powered analysis tools.

**`drift_detection.py`** — Behavioral drift detection engine. Uses sentence-transformers to embed reasoning traces and compare them against pre-built "safety manifolds" (reference embeddings per use case). Computes a drift coefficient D_c = 1 - cosine_similarity. Also scans for dangerous keyword patterns. Use cases: `loan_approval`, `hiring`, `medical_diagnosis`, `content_moderation`, `general`.

**`database.py`** — SQLAlchemy models and database setup. Three tables: `audit_records` (hash-chained ledger), `risk_scores`, `users`. Uses `compute_hash()` to chain audit records via SHA-256 hashes (blockchain-style immutable ledger).

**`governlayer_mcp.py`** — MCP server exposing 10 tools for Claude Desktop/MCP clients. Mirrors API functionality (audit, risk scoring, threat analysis, etc.) but without auth or database persistence. Uses LangChain + Groq (Llama 3.3 70B) and DuckDuckGo search.

## Key Technical Details

- JWT auth uses a hardcoded `SECRET_KEY` in `api.py` — this should be moved to env vars for production.
- The audit ledger is hash-chained: each record stores `previous_hash` and `current_hash`, starting from a genesis hash of `SHA256("GOVERNLAYER_GENESIS")`.
- Risk scoring is deterministic (not LLM-based) — boolean inputs map to fixed scores per dimension.
- Drift detection loads the transformer model and pre-computes manifolds at module import time.
- The Dockerfile omits `sentence-transformers` and `torch` to keep the image small, so the deployed version stubs out drift detection.
