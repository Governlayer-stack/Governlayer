"""Admin infrastructure diagnostic endpoints.

Gated by the ADMIN_KEY environment variable — this is not a user-facing route.
Purpose: answer "is my production infrastructure actually wired?" in one call.

The primary consumer is the operator (Ekene) hitting `GET /admin/infra-check`
from a browser on Railway to verify Redis, Sentry, Postgres, and LLM providers
are actually configured and reachable. Silently-misconfigured infra is the
root cause of hard-to-diagnose production outages; this endpoint makes the
answer trivially observable.
"""

from __future__ import annotations

import logging
import os
import socket
import time
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from src.config import get_settings
from src.models.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin_key(x_admin_key: str | None = Header(default=None)) -> None:
    """Guard every /admin/* endpoint with a shared secret."""
    s = get_settings()
    if not s.admin_key:
        raise HTTPException(
            status_code=503,
            detail="ADMIN_KEY not configured on this deployment.",
        )
    if not x_admin_key or x_admin_key != s.admin_key:
        raise HTTPException(status_code=401, detail="invalid or missing X-Admin-Key")


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> tuple[bool, float, str]:
    """Try to open a TCP socket to (host, port). Return (ok, ms, error)."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.perf_counter() - started) * 1000, 2), ""
    except (socket.timeout, socket.gaierror, OSError) as exc:
        return False, round((time.perf_counter() - started) * 1000, 2), str(exc)


def _check_redis(redis_url: str) -> dict[str, Any]:
    """Check whether Redis is reachable and NOT a localhost stub.

    A very common Railway misconfiguration is REDIS_URL left at the default
    `redis://localhost:6379/0` — which means rate limiting silently no-ops
    in production. This check flags that explicitly.
    """
    parsed = urlparse(redis_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    is_localhost = host in ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    ok, ms, err = _tcp_probe(host, port)

    verdict = "ok"
    warnings: list[str] = []
    if is_localhost:
        warnings.append(
            "REDIS_URL points at localhost. If this is Railway production, "
            "rate limiting is silently disabled. Set REDIS_URL to a Railway "
            "Redis add-on connection string."
        )
        verdict = "misconfigured"
    if not ok:
        warnings.append(f"TCP connect failed: {err}")
        verdict = "unreachable"

    return {
        "check": "redis",
        "verdict": verdict,
        "host": host,
        "port": port,
        "reachable": ok,
        "latency_ms": ms,
        "is_localhost": is_localhost,
        "warnings": warnings,
    }


def _check_sentry() -> dict[str, Any]:
    s = get_settings()
    dsn = s.sentry_dsn.strip()
    verdict = "ok"
    warnings: list[str] = []

    if not dsn:
        verdict = "missing"
        warnings.append(
            "SENTRY_DSN is empty. Error tracking is disabled — you will have "
            "no visibility into production 500s."
        )
    elif not dsn.startswith("https://"):
        verdict = "misconfigured"
        warnings.append("SENTRY_DSN does not start with https://")

    return {
        "check": "sentry",
        "verdict": verdict,
        "configured": bool(dsn),
        "dsn_prefix": dsn[:32] + "..." if dsn else None,
        "warnings": warnings,
    }


def _check_postgres(db: Session) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        result = db.execute(sa_text("SELECT 1")).scalar()
        latency = round((time.perf_counter() - started) * 1000, 2)
        version = db.execute(sa_text("SHOW server_version")).scalar()
        return {
            "check": "postgres",
            "verdict": "ok" if result == 1 else "unhealthy",
            "reachable": True,
            "latency_ms": latency,
            "server_version": str(version),
            "warnings": [],
        }
    except Exception as exc:  # noqa: BLE001 — diagnostic endpoint
        return {
            "check": "postgres",
            "verdict": "unreachable",
            "reachable": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "warnings": [f"query failed: {exc}"],
        }


def _check_llm_providers() -> dict[str, Any]:
    s = get_settings()
    providers = {
        "groq": bool(s.groq_api_key.strip()),
        "openrouter": bool(s.openrouter_api_key.strip()),
    }
    configured = sum(providers.values())
    verdict = "ok" if configured >= 1 else "missing"
    warnings: list[str] = []
    if configured == 0:
        warnings.append(
            "No cloud LLM provider configured. Any Achonye route to Groq or "
            "OpenRouter will fail. Set GROQ_API_KEY or OPENROUTER_API_KEY."
        )
    return {
        "check": "llm_providers",
        "verdict": verdict,
        "providers": providers,
        "warnings": warnings,
    }


def _check_stripe() -> dict[str, Any]:
    s = get_settings()
    configured = bool(s.stripe_api_key.strip())
    webhook_configured = bool(s.stripe_webhook_secret.strip())
    prices_configured = all([
        s.stripe_price_starter.strip(),
        s.stripe_price_pro.strip(),
        s.stripe_price_enterprise.strip(),
    ])
    verdict = "ok" if configured and webhook_configured and prices_configured else "partial"
    warnings: list[str] = []
    if not configured:
        warnings.append("STRIPE_API_KEY missing — billing endpoints will fail.")
    if not webhook_configured:
        warnings.append("STRIPE_WEBHOOK_SECRET missing — webhook verification off.")
    if not prices_configured:
        warnings.append("One or more STRIPE_PRICE_* env vars missing.")
    return {
        "check": "stripe",
        "verdict": verdict,
        "api_key": configured,
        "webhook_secret": webhook_configured,
        "prices": prices_configured,
        "warnings": warnings,
    }


def _check_cors() -> dict[str, Any]:
    s = get_settings()
    origins = s.cors_origins
    is_wildcard = origins.strip() == "*" or "*" in [o.strip() for o in origins.split(",")]
    verdict = "ok"
    warnings: list[str] = []
    if is_wildcard:
        verdict = "misconfigured"
        warnings.append(
            "CORS_ORIGINS is wildcard '*'. Lock it to https://www.governlayer.ai,"
            "https://governlayer.ai for production."
        )
    return {
        "check": "cors",
        "verdict": verdict,
        "origins": origins,
        "warnings": warnings,
    }


@router.get("/infra-check")
def infra_check(
    _: None = Depends(_require_admin_key),
    db: Session = Depends(get_db),
):
    """Run every infrastructure health check and return a structured report.

    Requires: X-Admin-Key header matching the ADMIN_KEY env var.

    Response includes an overall verdict (`healthy` / `degraded` / `broken`)
    plus a per-dependency breakdown. Use this from the Railway shell:

        curl -H "X-Admin-Key: $ADMIN_KEY" \\
            https://web-production-bdd26.up.railway.app/admin/infra-check

    A `verdict != "ok"` on any critical dependency will fail loudly rather
    than silently — this is intentional. The whole point is to surface
    misconfiguration before it causes a production incident.
    """
    s = get_settings()

    checks = [
        _check_postgres(db),
        _check_redis(s.redis_url),
        _check_sentry(),
        _check_llm_providers(),
        _check_stripe(),
        _check_cors(),
    ]

    critical_verdicts = {"unreachable", "misconfigured", "broken"}
    critical_failures = [c for c in checks if c["verdict"] in critical_verdicts]

    if critical_failures:
        overall = "broken" if any(c["verdict"] == "unreachable" for c in critical_failures) else "degraded"
    elif any(c["verdict"] == "missing" for c in checks):
        overall = "degraded"
    else:
        overall = "healthy"

    all_warnings: list[str] = []
    for c in checks:
        all_warnings.extend(c.get("warnings", []))

    return {
        "overall_verdict": overall,
        "environment": "production" if not s.debug else "development",
        "policy_version": s.policy_version,
        "checks": checks,
        "warning_count": len(all_warnings),
        "warnings": all_warnings,
    }


@router.get("/env-audit")
def env_audit(_: None = Depends(_require_admin_key)):
    """List which environment variables are set (values redacted).

    Useful for diagnosing "did the last Railway env change actually apply?"
    without exposing secrets.
    """
    s = get_settings()
    fields = {
        "SECRET_KEY": bool(s.secret_key) and s.secret_key != "CHANGE-ME-IN-PRODUCTION",
        "DATABASE_URL": bool(s.database_url),
        "REDIS_URL": bool(s.redis_url) and "localhost" not in s.redis_url,
        "SENTRY_DSN": bool(s.sentry_dsn),
        "GROQ_API_KEY": bool(s.groq_api_key),
        "OPENROUTER_API_KEY": bool(s.openrouter_api_key),
        "STRIPE_API_KEY": bool(s.stripe_api_key),
        "STRIPE_WEBHOOK_SECRET": bool(s.stripe_webhook_secret),
        "STRIPE_PRICE_STARTER": bool(s.stripe_price_starter),
        "STRIPE_PRICE_PRO": bool(s.stripe_price_pro),
        "STRIPE_PRICE_ENTERPRISE": bool(s.stripe_price_enterprise),
        "RESEND_API_KEY": bool(s.resend_api_key),
        "GOOGLE_CLIENT_ID": bool(s.google_client_id),
        "MICROSOFT_CLIENT_ID": bool(s.microsoft_client_id),
        "GITHUB_CLIENT_ID": bool(s.github_client_id),
        "OAUTH_REDIRECT_BASE": bool(s.oauth_redirect_base),
        "ADMIN_KEY": bool(s.admin_key),
        "PRIVATE_PITCH_SLUG": bool(s.private_pitch_slug),
        "PRIVATE_PITCH_HTML_GZ": bool(s.private_pitch_html_gz),
    }
    missing = [k for k, v in fields.items() if not v]
    return {
        "set_count": sum(1 for v in fields.values() if v),
        "missing_count": len(missing),
        "missing": missing,
        "fields": fields,
    }
