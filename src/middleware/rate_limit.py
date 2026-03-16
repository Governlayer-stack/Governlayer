"""Rate limiting middleware — per API key with plan-based tiers.

Uses Redis when available (multi-worker safe), falls back to in-memory.
"""

import logging
import time
from collections import defaultdict
from threading import Lock

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger("governlayer.ratelimit")

# Plan-based rate limits (requests per minute)
PLAN_LIMITS = {
    "free": 20,
    "starter": 100,
    "pro": 500,
    "enterprise": 2000,
}

# Try Redis, fall back to in-memory
_redis_client = None
try:
    import redis as _redis_mod

    from src.config import get_settings as _get_settings
    _redis_client = _redis_mod.from_url(_get_settings().redis_url, decode_responses=True)
    _redis_client.ping()
    logger.info("Rate limiter using Redis")
except Exception:
    logger.info("Rate limiter using in-memory (Redis unavailable)")
    _redis_client = None

# In-memory fallback
_buckets: dict[str, list[float]] = defaultdict(list)
_lock = Lock()


def _get_client_key(request: Request) -> str:
    """Extract rate limit key from request."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer gl_"):
        return f"apikey:{auth[7:17]}"  # Use key prefix
    return f"ip:{request.client.host}" if request.client else "ip:unknown"


def _check_rate(key: str, limit: int, window: int = 60) -> tuple[bool, int]:
    """Sliding window rate check. Returns (allowed, remaining)."""
    if _redis_client:
        return _check_rate_redis(key, limit, window)
    return _check_rate_memory(key, limit, window)


def _check_rate_redis(key: str, limit: int, window: int = 60) -> tuple[bool, int]:
    rkey = f"rl:{key}"
    try:
        pipe = _redis_client.pipeline()
        now = time.time()
        pipe.zremrangebyscore(rkey, 0, now - window)
        pipe.zcard(rkey)
        pipe.zadd(rkey, {str(now): now})
        pipe.expire(rkey, window)
        results = pipe.execute()
        count = results[1]
        if count >= limit:
            return False, 0
        return True, limit - count - 1
    except Exception:
        return _check_rate_memory(key, limit, window)


def _check_rate_memory(key: str, limit: int, window: int = 60) -> tuple[bool, int]:
    now = time.time()
    with _lock:
        _buckets[key] = [t for t in _buckets[key] if t > now - window]
        if len(_buckets[key]) >= limit:
            return False, 0
        _buckets[key].append(now)
        return True, limit - len(_buckets[key])


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health/docs endpoints
        path = request.url.path
        skip = path in ("/", "/docs", "/openapi.json", "/redoc", "/automate/health")
        skip = skip or path.startswith("/auth") or path.startswith("/v1/enterprise")
        if skip:
            return await call_next(request)

        client_key = _get_client_key(request)
        limit = PLAN_LIMITS["free"]  # Default; upgraded after auth via API key lookup

        allowed, remaining = _check_rate(client_key, limit)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Upgrade your plan for higher limits.",
                    "retry_after_seconds": 60,
                },
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
