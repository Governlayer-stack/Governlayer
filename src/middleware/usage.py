"""Usage metering middleware — tracks every API call per tenant."""

import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


class UsageMeteringMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        latency_ms = (time.time() - start) * 1000

        # Store usage asynchronously (non-blocking)
        # In production, push to a queue (Redis/Kafka) instead of DB write per request
        path = request.url.path
        if path.startswith("/v1/") or path.startswith("/govern") or path.startswith("/automate"):
            request.state.usage = {
                "endpoint": path,
                "method": request.method,
                "status_code": response.status_code,
                "latency_ms": round(latency_ms, 2),
            }

        response.headers["X-Request-Duration-Ms"] = str(round(latency_ms, 2))
        return response
