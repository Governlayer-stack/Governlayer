"""Rate limiting middleware — per API key with plan-based tiers.

Uses Redis when available (multi-worker safe), falls back to in-memory.
Enforces both per-minute rate limits and monthly usage quotas.
"""

import logging
import os
import time
from collections import defaultdict
from datetime import datetime
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

# Plan-based monthly usage caps (requests per calendar month)
PLAN_MONTHLY_CAPS = {
    "free": 500,
    "starter": 10_000,
    "pro": 100_000,
    "enterprise": None,  # unlimited
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

# Monthly quota cache: key -> (used_count, limit, plan, timestamp)
_monthly_cache: dict[str, tuple[int, int | None, str, float]] = {}
_monthly_cache_lock = Lock()
_MONTHLY_CACHE_TTL = 60  # seconds


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


def _resolve_plan_limit(request: Request) -> int:
    """Look up the actual plan limit from the API key's org, fall back to free tier."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer gl_"):
        return PLAN_LIMITS["free"]
    try:
        from src.models.database import SessionLocal
        from src.models.tenant import ApiKey, Organization, hash_api_key
        db = SessionLocal()
        try:
            key_hash = hash_api_key(auth[7:])
            api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True)).first()
            if api_key:
                org = db.query(Organization).filter(Organization.id == api_key.org_id).first()
                if org:
                    return PLAN_LIMITS.get(org.plan, PLAN_LIMITS["free"])
        finally:
            db.close()
    except Exception:
        pass
    return PLAN_LIMITS["free"]


def _check_monthly_quota(api_key_prefix: str) -> tuple[bool, int, int | None]:
    """Check monthly usage quota for an API key's org.

    Returns (allowed, used_count, monthly_limit).
    Uses an in-memory cache with 60s TTL to avoid hitting DB on every request.
    Fails open on any exception.
    """
    now = time.time()

    # Check cache first
    with _monthly_cache_lock:
        cached = _monthly_cache.get(api_key_prefix)
        if cached and (now - cached[3]) < _MONTHLY_CACHE_TTL:
            used, limit, plan, _ = cached
            if limit is None:  # unlimited
                return True, used, None
            return used < limit, used, limit

    # Cache miss or expired — query DB
    try:
        from sqlalchemy import func as sa_func

        from src.models.database import SessionLocal
        from src.models.tenant import ApiKey, Organization, UsageRecord

        db = SessionLocal()
        try:
            api_key = db.query(ApiKey).filter(
                ApiKey.key_prefix == api_key_prefix, ApiKey.is_active.is_(True)
            ).first()
            if not api_key:
                return True, 0, None

            org = db.query(Organization).filter(Organization.id == api_key.org_id).first()
            if not org:
                return True, 0, None

            plan = org.plan or "free"
            limit = PLAN_MONTHLY_CAPS.get(plan)

            # Enterprise has no cap
            if limit is None:
                with _monthly_cache_lock:
                    _monthly_cache[api_key_prefix] = (0, None, plan, now)
                return True, 0, None

            # Count usage for current month
            month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            used = db.query(sa_func.count(UsageRecord.id)).filter(
                UsageRecord.org_id == org.id,
                UsageRecord.created_at >= month_start,
            ).scalar() or 0

            # Update cache
            with _monthly_cache_lock:
                _monthly_cache[api_key_prefix] = (used, limit, plan, now)

            return used < limit, used, limit
        finally:
            db.close()
    except Exception as e:
        logger.debug("Monthly quota check failed (allowing): %s", e)
        return True, 0, None


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting in test mode
        if os.environ.get("TESTING"):
            return await call_next(request)

        # Skip rate limiting for health/docs endpoints
        path = request.url.path
        skip = path in ("/", "/docs", "/openapi.json", "/redoc", "/health", "/automate/health")
        skip = skip or path.startswith("/v1/enterprise")
        if skip:
            return await call_next(request)

        # Stricter rate limits for auth endpoints (brute-force protection)
        if path.startswith("/auth"):
            client_ip = f"ip:{request.client.host}" if request.client else "ip:unknown"
            if path.startswith("/auth/register"):
                auth_limit = 5
                auth_key = f"auth:register:{client_ip}"
            else:
                auth_limit = 10
                auth_key = f"auth:login:{client_ip}"
            allowed, remaining = _check_rate(auth_key, auth_limit, window=60)
            reset_time = int(time.time()) + 60
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "message": "Too many authentication attempts. Try again later.",
                        "retry_after_seconds": 60,
                    },
                    headers={
                        "Retry-After": "60",
                        "X-RateLimit-Limit": str(auth_limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset_time),
                    },
                )
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(auth_limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(reset_time)
            return response

        client_key = _get_client_key(request)
        limit = _resolve_plan_limit(request)

        allowed, remaining = _check_rate(client_key, limit)
        reset_time = int(time.time()) + 60
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Upgrade your plan for higher limits.",
                    "plan_limits": PLAN_LIMITS,
                    "retry_after_seconds": 60,
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_time),
                },
            )

        # Monthly quota check — only for metered paths with API key auth
        monthly_used = None
        monthly_limit = None
        metered_path = path.startswith("/v1/") or path.startswith("/govern") or path.startswith("/automate")
        auth = request.headers.get("authorization", "")
        has_api_key = auth.startswith("Bearer gl_")

        if metered_path and has_api_key:
            api_key_prefix = auth[7:15]  # gl_XXXXXXXX prefix
            quota_allowed, monthly_used, monthly_limit = _check_monthly_quota(api_key_prefix)
            if not quota_allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "monthly_quota_exceeded",
                        "message": "Monthly API quota exceeded. Upgrade your plan for higher limits.",
                        "used": monthly_used,
                        "limit": monthly_limit,
                        "plan_limits": PLAN_MONTHLY_CAPS,
                        "upgrade_url": "/billing/checkout",
                    },
                )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)

        # Add monthly usage headers when available
        if monthly_used is not None:
            response.headers["X-Monthly-Usage"] = str(monthly_used)
        if monthly_limit is not None:
            response.headers["X-Monthly-Limit"] = str(monthly_limit)

        return response
