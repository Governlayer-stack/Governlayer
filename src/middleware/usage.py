"""Usage metering middleware — tracks every API call per tenant."""

import logging
import time
from threading import Thread

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("governlayer.usage")


def _record_usage(endpoint: str, method: str, status_code: int, latency_ms: float, api_key_prefix: str | None):
    """Write usage record to DB in a background thread (non-blocking)."""
    if not api_key_prefix:
        return
    try:
        from src.models.database import SessionLocal
        from src.models.tenant import ApiKey, UsageRecord
        db = SessionLocal()
        try:
            api_key = db.query(ApiKey).filter(
                ApiKey.key_prefix == api_key_prefix, ApiKey.is_active.is_(True)
            ).first()
            if api_key:
                record = UsageRecord(
                    org_id=api_key.org_id,
                    api_key_id=api_key.id,
                    endpoint=endpoint,
                    method=method,
                    status_code=status_code,
                    latency_ms=latency_ms,
                )
                db.add(record)
                db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.debug("Usage recording skipped: %s", e)


class UsageMeteringMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        latency_ms = round((time.time() - start) * 1000, 2)

        path = request.url.path
        if path.startswith("/v1/") or path.startswith("/govern") or path.startswith("/automate"):
            # Extract API key prefix for tenant attribution
            auth = request.headers.get("authorization", "")
            api_key_prefix = None
            if auth.startswith("Bearer gl_"):
                api_key_prefix = auth[7:15]  # gl_XXXXXXXX prefix

            if api_key_prefix:
                Thread(
                    target=_record_usage,
                    args=(path, request.method, response.status_code, latency_ms, api_key_prefix),
                    daemon=True,
                ).start()

        response.headers["X-Request-Duration-Ms"] = str(latency_ms)
        return response
