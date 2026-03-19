"""Error tracking middleware — catches unhandled exceptions, logs structured errors.

Optionally forwards to Sentry if sentry-sdk is installed and SENTRY_DSN is set.
Never exposes internal details to clients.
"""

import logging
import os
import traceback
from collections import defaultdict
from threading import Lock

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger("governlayer.errors")

# Track error counts by endpoint (in-memory)
_error_counts: dict[str, int] = defaultdict(int)
_error_lock = Lock()

# Try to initialize Sentry (optional, no hard dependency)
_sentry_initialized = False


def init_sentry(dsn: str) -> None:
    """Initialize Sentry SDK if available and DSN is provided."""
    global _sentry_initialized
    if not dsn or _sentry_initialized:
        return
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=dsn, traces_sample_rate=0.1)
        _sentry_initialized = True
        logger.info("Sentry error tracking initialized")
    except ImportError:
        logger.debug("sentry-sdk not installed, skipping Sentry integration")
    except Exception as e:
        logger.warning("Sentry initialization failed: %s", e)


def get_error_counts() -> dict[str, int]:
    """Return a copy of error counts by endpoint."""
    with _error_lock:
        return dict(_error_counts)


def get_total_errors() -> int:
    """Return total error count across all endpoints."""
    with _error_lock:
        return sum(_error_counts.values())


class ErrorTrackingMiddleware(BaseHTTPMiddleware):
    """Catches unhandled exceptions and returns clean JSON errors."""

    async def dispatch(self, request: Request, call_next):
        # Skip in test mode — let exceptions propagate for test assertions
        if os.environ.get("TESTING"):
            return await call_next(request)

        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            path = request.url.path
            request_id = getattr(request.state, "request_id", "unknown")

            # Track error count
            with _error_lock:
                _error_counts[path] += 1

            # Log full structured error
            tb = traceback.format_exception(type(exc), exc, exc.__traceback__)
            log_data = {
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "path": path,
                "method": request.method,
                "request_id": request_id,
                "client_ip": request.client.host if request.client else "unknown",
                "traceback": "".join(tb),
            }

            if hasattr(request.state, "org_id"):
                log_data["org_id"] = request.state.org_id

            logger.error(
                "Unhandled exception on %s %s: %s",
                request.method,
                path,
                type(exc).__name__,
                extra={"structured_data": log_data},
            )

            # Forward to Sentry if initialized
            if _sentry_initialized:
                try:
                    import sentry_sdk
                    sentry_sdk.capture_exception(exc)
                except Exception:
                    pass

            # Return clean error — never expose internals
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_server_error",
                    "message": "An unexpected error occurred. Please try again later.",
                    "request_id": request_id,
                },
                headers={
                    "X-Request-ID": request_id,
                },
            )
