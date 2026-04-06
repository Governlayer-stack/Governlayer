# === Stage 1: Builder ===
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements/ requirements/
# Prefer lockfile for reproducible builds; fall back to prod.txt
RUN if [ -f requirements/base.lock ]; then \
      pip install --no-cache-dir --prefix=/install -r requirements/base.lock; \
    else \
      pip install --no-cache-dir --prefix=/install -r requirements/prod.txt; \
    fi

# === Stage 2: Production ===
FROM python:3.11-slim AS production

# Security: non-root user
RUN groupadd -r governlayer && useradd -r -g governlayer governlayer

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Cache-buster: changes on every deploy to force fresh COPY
COPY .railway-trigger /tmp/.railway-trigger

# Copy application code
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .
COPY docs/ docs/
COPY dashboard/dist/ dashboard/dist/

# Own the app dir
RUN chown -R governlayer:governlayer /app

USER governlayer

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-8000}/health')" || exit 1

EXPOSE 8000

CMD ["sh", "-c", "uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2"]
