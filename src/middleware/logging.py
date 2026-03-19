"""Structured JSON logging middleware — every request logged with context.

Adds X-Request-ID header, logs method/path/status/latency/client info.
Skips health check noise. Logs errors with full traceback.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("governlayer.access")

# Paths that generate noise in logs — skip them
_SKIP_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico"})


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge extra structured data if present
        if hasattr(record, "structured_data"):
            log_entry.update(record.structured_data)
        # Include traceback for errors
        if record.exc_info and record.exc_info[2]:
            log_entry["traceback"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Set up root logger with JSON or text formatting."""
    root = logging.getLogger("governlayer")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates on reload
    root.handlers.clear()

    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
        ))
    root.addHandler(handler)
    root.propagate = False


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request in structured format with request ID tracking."""

    async def dispatch(self, request: Request, call_next):
        # Skip in test mode
        if os.environ.get("TESTING"):
            return await call_next(request)

        # Generate or reuse request ID
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id

        path = request.url.path

        # Skip noisy paths
        if path in _SKIP_PATHS:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response

        start = time.monotonic()
        status_code = 500  # default if exception

        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            latency_ms = round((time.monotonic() - start) * 1000, 2)

            # Build structured log data
            log_data = {
                "method": request.method,
                "path": path,
                "status": status_code,
                "latency_ms": latency_ms,
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", ""),
                "request_id": request_id,
            }

            # Extract org/key info from auth header (non-blocking)
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer gl_"):
                log_data["api_key_prefix"] = auth[7:15]
            # Extract org_id if set by auth middleware
            if hasattr(request.state, "org_id"):
                log_data["org_id"] = request.state.org_id

            level = logging.INFO
            if status_code >= 500:
                level = logging.ERROR
            elif status_code >= 400:
                level = logging.WARNING

            record = logger.makeRecord(
                name=logger.name,
                level=level,
                fn="",
                lno=0,
                msg=f"{request.method} {path} {status_code} {latency_ms}ms",
                args=(),
                exc_info=None,
            )
            record.structured_data = log_data
            logger.handle(record)
