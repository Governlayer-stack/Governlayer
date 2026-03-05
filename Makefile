.PHONY: help dev test lint docker-up docker-down db-init db-migrate mcp setup install ollama-pull

PYTHON := /opt/homebrew/bin/python3.11
VENV := venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# === Development ===

setup: ## Full local setup (venv + deps + db)
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements/dev.txt
	$(PY) -m src.models.database

install: ## Install dependencies only
	$(PIP) install -r requirements/dev.txt

dev: ## Run API server in dev mode
	$(PY) -m uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

mcp: ## Run MCP server
	$(PY) -m src.mcp.server

# === Testing ===

test: ## Run all tests
	$(PY) -m pytest tests/ -v

test-drift: ## Run drift detection tests
	$(PY) -m pytest tests/test_drift.py -v

test-one: ## Run a single test (usage: make test-one TEST=tests/test_drift.py::test_name)
	$(PY) -m pytest $(TEST) -v

lint: ## Run linting
	$(PY) -m ruff check src/ tests/
	$(PY) -m ruff format --check src/ tests/

format: ## Auto-format code
	$(PY) -m ruff format src/ tests/

# === Database ===

db-init: ## Initialize database tables
	$(PY) -m src.models.database

db-migrate: ## Run Alembic migrations
	$(PY) -m alembic upgrade head

db-revision: ## Create new Alembic migration (usage: make db-revision MSG="add xyz")
	$(PY) -m alembic revision --autogenerate -m "$(MSG)"

# === Docker ===

docker-up: ## Start full stack (API + Postgres + Redis)
	docker compose up -d

docker-down: ## Stop all containers
	docker compose down

docker-build: ## Rebuild API container
	docker compose build api

docker-logs: ## Tail all container logs
	docker compose logs -f

docker-local-llm: ## Start stack with Ollama for local inference
	docker compose --profile local-llm up -d

# === Ollama ===

ollama-pull: ## Pull default models for local inference
	ollama pull llama3:8b
	ollama pull codellama:7b
	ollama pull nomic-embed-text
