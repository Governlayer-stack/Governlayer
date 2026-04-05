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

# Copy application code
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .
COPY docs/landing/ docs/landing/
COPY docs/dashboard/ docs/dashboard/
COPY docs/documentation/ docs/documentation/
COPY docs/playground/ docs/playground/
COPY docs/onboarding/ docs/onboarding/
COPY docs/pitch/ docs/pitch/
COPY docs/demo/ docs/demo/
COPY docs/soc2/ docs/soc2/
COPY docs/competitive/ docs/competitive/
COPY docs/trust/ docs/trust/
COPY docs/auditor/ docs/auditor/
COPY docs/beta/ docs/beta/
COPY docs/legal/ docs/legal/
COPY docs/soc2-checklist/ docs/soc2-checklist/
COPY docs/compliance-checklist/ docs/compliance-checklist/
COPY docs/signup/ docs/signup/
COPY docs/workspace/ docs/workspace/
COPY docs/terms/ docs/terms/
COPY docs/privacy/ docs/privacy/

# Own the app dir
RUN chown -R governlayer:governlayer /app

USER governlayer

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-8000}/health')" || exit 1

EXPOSE 8000

CMD ["sh", "-c", "uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2"]
