# === Stage 1: Builder ===
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements/ requirements/
RUN pip install --no-cache-dir --prefix=/install -r requirements/prod.txt

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

# Own the app dir
RUN chown -R governlayer:governlayer /app

USER governlayer

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
