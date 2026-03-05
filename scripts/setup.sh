#!/usr/bin/env bash
set -euo pipefail

# GovernLayer Station Setup
# Installs all required tools for the autonomous agentic ecosystem

echo "=== GovernLayer Station Setup ==="
echo ""

# --- Homebrew packages ---
echo "[1/6] Installing system dependencies..."
brew install --quiet docker docker-compose gh ollama redis 2>/dev/null || true

# --- Docker Desktop check ---
echo "[2/6] Checking Docker..."
if ! docker info &>/dev/null; then
    echo "  Docker Desktop not running. Install from: https://docker.com/products/docker-desktop"
    echo "  Or use colima: brew install colima && colima start"
fi

# --- Python venv ---
echo "[3/6] Setting up Python 3.11 virtual environment..."
PYTHON="/opt/homebrew/bin/python3.11"
if [ ! -d "venv" ]; then
    $PYTHON -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements/dev.txt -q

# --- Redis ---
echo "[4/6] Starting Redis..."
brew services start redis 2>/dev/null || true

# --- Ollama ---
echo "[5/6] Setting up Ollama..."
if command -v ollama &>/dev/null; then
    echo "  Pulling default models (this may take a while on first run)..."
    ollama pull llama3:8b 2>/dev/null || true
    ollama pull nomic-embed-text 2>/dev/null || true
else
    echo "  Ollama not found. Install: brew install ollama"
fi

# --- Database ---
echo "[6/6] Initializing database..."
python -m src.models.database

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Quick start:"
echo "  make dev          # Start API server"
echo "  make test         # Run tests"
echo "  make mcp          # Start MCP server"
echo "  make docker-up    # Start full Docker stack"
echo ""
