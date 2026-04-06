"""GovernLayer API — application factory."""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import text as sa_text
from starlette.middleware.base import BaseHTTPMiddleware

from src.api import (
    achonye, agent_registry, analytics, analytics_usage, audit, auth, automation,
    billing, compliance_hub, controls, dashboard, enterprise, enterprise_features,
    evidence, governance, growth, incidents, integrations, knowledge_graph, ledger,
    mfa, policies, rbac_views, registry, reports, risk, threats, v1, vendor_risk,
)
from src.config import get_settings
from src.models.database import create_tables, SessionLocal
from src.models.schemas import DriftRequest
from src.security.auth import verify_token

logger = logging.getLogger("governlayer")


def _seed_demo_data():
    """Seed demo data on first startup so the dashboard isn't empty."""
    db = SessionLocal()
    try:
        from src.models.registry import RegisteredModel, Incident, ModelLifecycle, IncidentSeverity, IncidentStatus
        from src.models.policy import GovernancePolicy
        from src.models.agents import AIAgent, AgentType, AgentStatus, DiscoverySource
        from datetime import datetime

        # Only seed if DB is empty
        if db.query(RegisteredModel).count() > 0:
            return

        # Seed models
        models = [
            RegisteredModel(name="loan-approval-v3", version="3.2.1", provider="xgboost", model_type="classifier",
                            description="Credit risk scoring model for consumer loans",
                            owner="ml-platform@company.com",
                            lifecycle=ModelLifecycle.PRODUCTION, governance_status="compliant", risk_score=34.0),
            RegisteredModel(name="fraud-detector", version="2.1.0", provider="pytorch", model_type="classifier",
                            description="Real-time transaction fraud detection",
                            owner="fraud-team@company.com",
                            lifecycle=ModelLifecycle.PRODUCTION, governance_status="compliant", risk_score=45.0),
            RegisteredModel(name="content-moderator", version="1.5.0", provider="huggingface", model_type="transformer",
                            description="User-generated content safety classifier",
                            owner="trust-safety@company.com",
                            lifecycle=ModelLifecycle.STAGING, governance_status="pending", risk_score=62.0),
            RegisteredModel(name="resume-screener", version="0.9.0", provider="sklearn", model_type="classifier",
                            description="Candidate resume ranking model",
                            owner="hr-tech@company.com",
                            lifecycle=ModelLifecycle.DEVELOPMENT, governance_status="non_compliant", risk_score=78.0),
            RegisteredModel(name="chatbot-support", version="4.0.0", provider="openai", model_type="llm",
                            description="Customer support conversational AI",
                            owner="cx-team@company.com",
                            lifecycle=ModelLifecycle.PRODUCTION, governance_status="compliant", risk_score=22.0),
        ]
        db.add_all(models)

        # Seed incidents
        incidents = [
            Incident(title="Data drift detected in fraud-detector inputs",
                     description="PSI score exceeded threshold on transaction_amount feature",
                     severity=IncidentSeverity.HIGH, status=IncidentStatus.INVESTIGATING,
                     affected_system="fraud-detector", category="data_drift",
                     reporter="monitoring-bot"),
            Incident(title="Resume screener bias flag — gender disparity",
                     description="Disparate impact ratio dropped below 0.8 for gender dimension",
                     severity=IncidentSeverity.CRITICAL, status=IncidentStatus.OPEN,
                     affected_system="resume-screener", category="fairness",
                     reporter="fairness-audit"),
            Incident(title="Content moderator false positive spike",
                     description="False positive rate increased 15% after model update",
                     severity=IncidentSeverity.MEDIUM, status=IncidentStatus.OPEN,
                     affected_system="content-moderator", category="performance",
                     reporter="ml-ops"),
        ]
        db.add_all(incidents)

        # Seed policy
        policy = GovernancePolicy(
            name="Enterprise Default Policy",
            version="1.0",
            description="Standard governance policy for all production AI models",
            is_active=True,
            rules=[
                {"name": "risk_threshold", "condition": "risk_score <= 70", "action": "allow", "message": "Risk score within acceptable range"},
                {"name": "drift_threshold", "condition": "drift_coefficient <= 0.30", "action": "allow", "message": "Drift within acceptable range"},
                {"name": "human_oversight", "condition": "has_human_oversight == True", "action": "warn", "message": "Human oversight recommended"},
                {"name": "fairness_check", "condition": "fairness_score >= 70", "action": "allow", "message": "Fairness score acceptable"},
                {"name": "high_risk_block", "condition": "risk_score <= 90", "action": "allow", "message": "Extreme risk blocked"},
            ],
        )
        db.add(policy)

        # Seed agents
        agents = [
            AIAgent(name="support-chatbot-v2", agent_type=AgentType.CHATBOT,
                    status=AgentStatus.APPROVED, description="Customer support conversational AI",
                    owner="cx-team@company.com", team="Customer Experience",
                    purpose="Handle tier-1 support tickets via chat",
                    model_provider="OpenAI", model_name="gpt-4o",
                    tools=["ticket_lookup", "knowledge_base", "escalation"],
                    autonomy_level=2, risk_tier="medium", risk_score=35.0,
                    governance_status="compliant", discovery_source=DiscoverySource.MANUAL,
                    is_shadow=False, approved_by="ciso@company.com",
                    approved_at=datetime.utcnow(), first_seen_at=datetime.utcnow()),
            AIAgent(name="code-review-agent", agent_type=AgentType.TOOL_AGENT,
                    status=AgentStatus.APPROVED, description="Automated code review assistant",
                    owner="devtools@company.com", team="Engineering",
                    purpose="Review PRs for security vulnerabilities and code quality",
                    model_provider="Anthropic", model_name="claude-sonnet-4-20250514",
                    tools=["github_api", "static_analysis", "dependency_check"],
                    autonomy_level=1, risk_tier="low", risk_score=18.0,
                    governance_status="compliant", discovery_source=DiscoverySource.MANUAL,
                    is_shadow=False, first_seen_at=datetime.utcnow()),
            AIAgent(name="unknown-gpt-usage", agent_type=AgentType.AUTONOMOUS,
                    status=AgentStatus.UNDER_REVIEW, description="Unregistered GPT-4 API usage detected in marketing department",
                    owner="unknown", team="Marketing",
                    purpose="Unknown — detected via API traffic scan",
                    model_provider="OpenAI", model_name="gpt-4",
                    autonomy_level=3, risk_tier="high", risk_score=72.0,
                    governance_status="non_compliant", discovery_source=DiscoverySource.API_SCAN,
                    is_shadow=True, first_seen_at=datetime.utcnow()),
        ]
        db.add_all(agents)

        db.commit()
        logger.info("Seeded demo data: 5 models, 3 incidents, 1 policy, 3 agents")
    except Exception as e:
        db.rollback()
        logger.warning("Demo seed skipped: %s", e)
    finally:
        db.close()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' https://web-production-bdd26.up.railway.app"
        )
        return response

CONTACTS_FILE = Path("/tmp/governlayer_contacts.json")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ContactRequest(BaseModel):
    name: str
    email: str
    company: str
    message: str = ""
    form_type: str = Field(default="demo")


FRAMEWORKS = [
    "NIST_AI_RMF", "EU_AI_ACT", "ISO_42001", "ISO_27001", "NIS2", "DORA",
    "MITRE_ATLAS", "OWASP_AI", "SOC2", "GDPR", "CCPA", "HIPAA",
    "IEEE_ETHICS", "OECD_AI", "NIST_CSF", "UNESCO_AI", "SINGAPORE_AI",
    "UK_AI", "CANADA_AIDA", "CHINA_AI", "COBIT", "ITIL",
    "ZERO_TRUST", "CIS_CONTROLS", "FAIR_RISK", "CSA_AI", "US_EO_AI",
    "DSA", "DMA",
]


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="GovernLayer API",
        description=(
            "The Governance Layer for Agentic AI — agent registry, shadow AI discovery, "
            "compliance auditing, drift detection, risk scoring, policy engine, "
            "and immutable audit ledger for enterprise AI systems.\n\n"
            "## Quick Start\n"
            "1. Create an organization: `POST /v1/enterprise/orgs`\n"
            "2. Generate an API key: `POST /v1/enterprise/orgs/{slug}/api-keys`\n"
            "3. Run governance: `POST /v1/govern` with `Authorization: Bearer gl_xxx`\n\n"
            "## Authentication\n"
            "- **API Key** (recommended): `Authorization: Bearer gl_xxxxx`\n"
            "- **JWT**: Register at `/auth/register`, then use the returned token\n"
        ),
        version=settings.policy_version,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    allowed_origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()] if settings.cors_origins else []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    )
    app.add_middleware(SecurityHeadersMiddleware)

    from src.middleware.rate_limit import RateLimitMiddleware
    from src.middleware.usage import UsageMeteringMiddleware
    from src.middleware.logging import StructuredLoggingMiddleware, configure_logging
    from src.middleware.error_tracking import ErrorTrackingMiddleware, init_sentry
    from src.middleware.metrics import MetricsMiddleware, metrics

    # Configure structured logging
    configure_logging(level=settings.log_level, fmt=settings.log_format)

    # Initialize Sentry if configured
    if settings.sentry_dsn:
        init_sentry(settings.sentry_dsn)

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(UsageMeteringMiddleware)
    app.add_middleware(StructuredLoggingMiddleware)
    app.add_middleware(ErrorTrackingMiddleware)
    # MetricsMiddleware is raw ASGI — add via app constructor
    app.add_middleware(MetricsMiddleware)

    # Register routers
    app.include_router(auth.router)
    app.include_router(mfa.router)
    app.include_router(governance.router)
    app.include_router(audit.router)
    app.include_router(risk.router)
    app.include_router(ledger.router)
    app.include_router(threats.router)
    app.include_router(achonye.router)
    app.include_router(automation.router)
    app.include_router(enterprise.router)
    app.include_router(billing.router)
    app.include_router(v1.router)
    app.include_router(registry.router)
    app.include_router(incidents.router)
    app.include_router(analytics.router)
    app.include_router(analytics_usage.router)
    app.include_router(policies.router)
    app.include_router(reports.router)
    app.include_router(dashboard.router)
    app.include_router(agent_registry.router)
    app.include_router(integrations.router)
    app.include_router(knowledge_graph.router)
    app.include_router(rbac_views.router)
    app.include_router(enterprise_features.router)
    app.include_router(growth.router)
    app.include_router(vendor_risk.router)
    app.include_router(controls.router)
    app.include_router(evidence.router)
    app.include_router(compliance_hub.router)

    # Mount React dashboard (built SPA)
    _dashboard_dist = None
    for _ddir in [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "dist"),
        os.path.join("/app", "dashboard", "dist"),
    ]:
        if os.path.isdir(_ddir):
            _dashboard_dist = _ddir
            break
    if _dashboard_dist:
        app.mount("/dashboard", StaticFiles(directory=_dashboard_dist, html=True), name="dashboard")

    @app.on_event("startup")
    def startup():
        create_tables()
        _ensure_schema_columns()
        _seed_demo_data()

    def _ensure_schema_columns():
        """Legacy schema patches — these should be converted to proper Alembic migrations."""
        from src.models.database import SessionLocal
        logger.info("Running legacy schema patches (should be migrated to Alembic)")
        db = SessionLocal()
        try:
            for stmt in [
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(64)",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires_at TIMESTAMP",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(32)",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_codes TEXT",
                "ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS org_id VARCHAR",
                "ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS org_id VARCHAR",
            ]:
                try:
                    db.execute(sa_text(stmt))
                except Exception:
                    # Column already exists or table not yet created — safe to ignore
                    db.rollback()
                    continue
            db.commit()
        except Exception:
            # Schema patches are best-effort; failures are non-fatal
            db.rollback()
        finally:
            db.close()

    @app.get("/health")
    def health_check():
        """Lightweight health check for load balancers and monitoring."""
        from src.models.database import SessionLocal
        try:
            db = SessionLocal()
            db.execute(sa_text("SELECT 1"))
            db.close()
            db_status = "connected"
        except Exception:
            db_status = "unavailable"
        return {
            "status": "healthy" if db_status == "connected" else "degraded",
            "version": settings.policy_version,
            "database": db_status,
        }

    def _check_admin_key(request: Request):
        """Verify X-Admin-Key header for protected internal endpoints.

        If admin_key is not configured, allow access only when debug mode is on.
        """
        if settings.admin_key:
            provided = request.headers.get("x-admin-key", "")
            if provided != settings.admin_key:
                return JSONResponse(
                    status_code=403,
                    content={"error": "forbidden", "message": "Invalid or missing X-Admin-Key header"},
                )
        elif not settings.debug:
            return JSONResponse(
                status_code=403,
                content={"error": "forbidden", "message": "Admin key not configured. Set ADMIN_KEY in environment."},
            )
        return None

    @app.get("/metrics")
    def metrics_endpoint(request: Request):
        """Application metrics for monitoring dashboards."""
        denied = _check_admin_key(request)
        if denied:
            return denied
        from src.middleware.metrics import metrics as m
        data = m.snapshot()

        # Add database pool info
        try:
            from src.models.database import engine as db_engine
            pool = db_engine.pool
            data["database_pool"] = {
                "size": pool.size(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
            }
        except Exception:
            data["database_pool"] = {"status": "unavailable"}

        data["version"] = settings.policy_version
        data["started_at"] = datetime.fromtimestamp(
            m.started_at, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Include error counts by endpoint
        from src.middleware.error_tracking import get_error_counts
        data["errors_by_endpoint"] = get_error_counts()

        return data

    @app.get("/status")
    async def detailed_status():
        """Detailed status for uptime monitoring services (UptimeRobot, Betterstack, etc.)."""
        checks = {"api": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

        # Check database
        try:
            db = SessionLocal()
            db.execute(sa_text("SELECT 1"))
            db.close()
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "degraded"

        # Check Redis
        try:
            import redis
            r = redis.from_url(settings.redis_url, decode_responses=True)
            r.ping()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "not_configured"

        overall = "operational" if checks.get("database") == "ok" else "degraded"
        checks["status"] = overall
        checks["version"] = settings.policy_version
        return checks

    @app.get("/status/badge")
    async def status_badge():
        """SVG badge showing operational status (shields.io style)."""
        # Determine status by checking database
        try:
            db = SessionLocal()
            db.execute(sa_text("SELECT 1"))
            db.close()
            db_ok = True
        except Exception:
            db_ok = False

        if db_ok:
            label_text = "Operational"
            color = "#4c1"       # green
            label_width = 90
        else:
            label_text = "Degraded"
            color = "#dfb317"    # yellow
            label_width = 72

        prefix_text = "GovernLayer"
        prefix_width = 92
        total_width = prefix_width + label_width

        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="b" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <rect width="{prefix_width}" height="20" fill="#555"/>
    <rect x="{prefix_width}" width="{label_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{prefix_width / 2}" y="15" fill="#010101" fill-opacity=".3">{prefix_text}</text>
    <text x="{prefix_width / 2}" y="14">{prefix_text}</text>
    <text x="{prefix_width + label_width / 2}" y="15" fill="#010101" fill-opacity=".3">{label_text}</text>
    <text x="{prefix_width + label_width / 2}" y="14">{label_text}</text>
  </g>
</svg>"""
        return Response(content=svg, media_type="image/svg+xml")

    @app.get("/status/page", response_class=HTMLResponse)
    def status_page(request: Request):
        """Human-readable status page with dark theme."""
        denied = _check_admin_key(request)
        if denied:
            return denied

        from src.middleware.metrics import metrics as m
        from src.middleware.error_tracking import get_total_errors

        snap = m.snapshot()

        # Check database
        db_ok = False
        try:
            db = SessionLocal()
            db.execute(sa_text("SELECT 1"))
            db.close()
            db_ok = True
        except Exception:
            pass

        # Check Redis
        redis_ok = False
        try:
            import redis
            r = redis.from_url(settings.redis_url, decode_responses=True)
            r.ping()
            redis_ok = True
        except Exception:
            pass

        overall = "UP" if db_ok else "DEGRADED"
        overall_color = "#4ade80" if db_ok else "#facc15"

        uptime_pct = 100.0  # We track within process lifetime only
        if snap["total_requests"] > 0:
            uptime_pct = round((1.0 - snap["error_rate"]) * 100, 2)

        def _indicator(ok: bool) -> str:
            color = "#4ade80" if ok else "#ef4444"
            label = "Operational" if ok else "Down"
            return f'<span style="color:{color}; font-weight:600;">{label}</span>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GovernLayer Status</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; min-height: 100vh;
         display: flex; justify-content: center; padding: 2rem; }}
  .container {{ max-width: 640px; width: 100%; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .subtitle {{ color: #94a3b8; margin-bottom: 2rem; font-size: 0.9rem; }}
  .status-banner {{ background: #1e293b; border-radius: 12px; padding: 1.5rem;
                    margin-bottom: 1.5rem; text-align: center; }}
  .status-banner .label {{ font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.5rem; }}
  .status-banner .value {{ font-size: 2rem; font-weight: 700; color: {overall_color}; }}
  .card {{ background: #1e293b; border-radius: 10px; padding: 1.25rem;
           margin-bottom: 1rem; }}
  .card h2 {{ font-size: 0.95rem; color: #94a3b8; margin-bottom: 0.75rem;
              text-transform: uppercase; letter-spacing: 0.05em; }}
  .row {{ display: flex; justify-content: space-between; padding: 0.5rem 0;
          border-bottom: 1px solid #334155; }}
  .row:last-child {{ border-bottom: none; }}
  .row .key {{ color: #cbd5e1; }}
  .row .val {{ font-weight: 600; }}
  .footer {{ text-align: center; color: #475569; font-size: 0.8rem; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>GovernLayer Status</h1>
  <p class="subtitle">v{settings.policy_version} &mdash; Real-time system health</p>

  <div class="status-banner">
    <div class="label">Current Status</div>
    <div class="value">{overall}</div>
  </div>

  <div class="card">
    <h2>Components</h2>
    <div class="row"><span class="key">API Server</span><span class="val">{_indicator(True)}</span></div>
    <div class="row"><span class="key">Database</span><span class="val">{_indicator(db_ok)}</span></div>
    <div class="row"><span class="key">Cache (Redis)</span><span class="val">{_indicator(redis_ok)}</span></div>
  </div>

  <div class="card">
    <h2>Performance</h2>
    <div class="row"><span class="key">Uptime (success rate)</span><span class="val">{uptime_pct}%</span></div>
    <div class="row"><span class="key">Avg Response Time</span><span class="val">{snap['avg_latency_ms']} ms</span></div>
    <div class="row"><span class="key">Requests/min</span><span class="val">{snap['requests_per_minute']}</span></div>
    <div class="row"><span class="key">Total Requests</span><span class="val">{snap['total_requests']:,}</span></div>
    <div class="row"><span class="key">Active Connections</span><span class="val">{snap['active_connections']}</span></div>
    <div class="row"><span class="key">Error Rate</span><span class="val">{snap['error_rate'] * 100:.2f}%</span></div>
    <div class="row"><span class="key">Uptime</span><span class="val">{snap['uptime_seconds']:.0f}s</span></div>
  </div>

  <p class="footer">GovernLayer &mdash; The Governance Layer for Agentic AI</p>
</div>
</body>
</html>"""
        return HTMLResponse(html)

    # Load documentation page HTML once at startup
    _docs_html = None
    _docs_paths = [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "documentation", "index.html"),
        os.path.join("/app", "docs", "documentation", "index.html"),
    ]
    for _dpath in _docs_paths:
        if os.path.exists(_dpath):
            with open(_dpath) as f:
                _docs_html = f.read()
            break

    @app.get("/documentation")
    def documentation_page():
        if _docs_html:
            return HTMLResponse(_docs_html)
        return {"error": "Documentation page not found"}

    # Load playground HTML once at startup
    _playground_html = None
    for _ppath in [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "playground", "index.html"),
        os.path.join("/app", "docs", "playground", "index.html"),
    ]:
        if os.path.exists(_ppath):
            with open(_ppath) as f:
                _playground_html = f.read()
            break

    @app.get("/playground")
    def playground_page():
        if _playground_html:
            return HTMLResponse(_playground_html)
        return {"error": "Playground not found"}

    # Load onboarding HTML once at startup
    _onboarding_html = None
    for _opath in [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "onboarding", "index.html"),
        os.path.join("/app", "docs", "onboarding", "index.html"),
    ]:
        if os.path.exists(_opath):
            with open(_opath) as f:
                _onboarding_html = f.read()
            break

    @app.get("/onboarding")
    def onboarding_page():
        if _onboarding_html:
            return HTMLResponse(_onboarding_html)
        return {"error": "Onboarding not found"}

    # Helper to load HTML from docs/<name>/index.html
    def _load_page(name):
        for base in [os.path.dirname(os.path.dirname(__file__)), "/app"]:
            p = os.path.join(base, "docs", name, "index.html")
            if os.path.exists(p):
                with open(p) as f:
                    return f.read()
        return None

    _pitch_html = _load_page("pitch")
    _demo_html = _load_page("demo")
    _soc2_html = _load_page("soc2")
    _competitive_html = _load_page("competitive")
    _trust_html = _load_page("trust")
    _auditor_html = _load_page("auditor")
    _beta_html = _load_page("beta")
    _legal_html = _load_page("legal")
    _soc2_checklist_html = _load_page("soc2-checklist")
    _compliance_checklist_html = _load_page("compliance-checklist")
    _signup_html = _load_page("signup")
    _workspace_html = _load_page("workspace")
    _terms_html = _load_page("terms")
    _privacy_html = _load_page("privacy")
    _changelog_html = _load_page("changelog")
    _blog_html = _load_page("blog")
    _404_html = _load_page("404")

    @app.exception_handler(404)
    async def custom_404_handler(request: Request, exc):
        if request.url.path.startswith("/v1/") or request.url.path.startswith("/api/"):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        if _404_html:
            return HTMLResponse(content=_404_html, status_code=404)
        return JSONResponse(status_code=404, content={"detail": "Not found"})

    @app.get("/workspace")
    def workspace_page():
        if _workspace_html:
            return HTMLResponse(_workspace_html)
        return {"error": "Workspace page not found"}

    @app.get("/signup")
    def signup_page():
        if _signup_html:
            return HTMLResponse(_signup_html)
        return {"error": "Signup page not found"}

    @app.get("/compliance-checklist")
    def compliance_checklist_page():
        if _compliance_checklist_html:
            return HTMLResponse(_compliance_checklist_html)
        return {"error": "Compliance checklist page not found"}

    @app.get("/soc2-checklist")
    def soc2_checklist_page():
        if _soc2_checklist_html:
            return HTMLResponse(_soc2_checklist_html)
        return {"error": "SOC 2 checklist page not found"}

    @app.get("/legal")
    def legal_page():
        if _legal_html:
            return HTMLResponse(_legal_html)
        return {"error": "Legal agreement page not found"}

    @app.get("/beta")
    def beta_page():
        if _beta_html:
            return HTMLResponse(_beta_html)
        return {"error": "Beta program page not found"}

    @app.get("/pitch")
    def pitch_page():
        if _pitch_html:
            return HTMLResponse(_pitch_html)
        return {"error": "Pitch deck not found"}

    @app.get("/demo")
    def demo_page():
        if _demo_html:
            return HTMLResponse(_demo_html)
        return {"error": "Demo not found"}

    @app.get("/soc2")
    def soc2_page():
        if _soc2_html:
            return HTMLResponse(_soc2_html)
        return {"error": "SOC 2 page not found"}

    @app.get("/competitive")
    def competitive_page():
        if _competitive_html:
            return HTMLResponse(_competitive_html)
        return {"error": "Competitive analysis not found"}

    @app.get("/trust")
    def trust_center():
        if _trust_html:
            return HTMLResponse(_trust_html)
        return {"error": "Trust Center not found"}

    @app.get("/auditor")
    def auditor_portal():
        if _auditor_html:
            return HTMLResponse(_auditor_html)
        return {"error": "Auditor portal not found"}

    @app.get("/terms")
    def terms_page():
        if _terms_html:
            return HTMLResponse(_terms_html)
        return {"error": "Terms of Service not found"}

    @app.get("/privacy")
    def privacy_page():
        if _privacy_html:
            return HTMLResponse(_privacy_html)
        return {"error": "Privacy Policy not found"}

    @app.get("/changelog")
    def changelog_page():
        if _changelog_html:
            return HTMLResponse(_changelog_html)
        return {"error": "Changelog not found"}

    @app.get("/blog")
    def blog_page():
        if _blog_html:
            return HTMLResponse(_blog_html)
        return {"error": "Blog not found"}

    # Load landing page HTML once at startup
    _landing_html = None
    _landing_paths = [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "landing", "index.html"),
        os.path.join("/app", "docs", "landing", "index.html"),
    ]
    for _path in _landing_paths:
        if os.path.exists(_path):
            with open(_path) as f:
                _landing_html = f.read()
            break

    # Resolve og-image path once at startup
    _og_image_path = None
    for _og_path in [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "landing", "og-image.svg"),
        os.path.join("/app", "docs", "landing", "og-image.svg"),
    ]:
        if os.path.exists(_og_path):
            _og_image_path = _og_path
            break

    @app.get("/og-image.svg")
    def og_image():
        if _og_image_path and os.path.exists(_og_image_path):
            return FileResponse(_og_image_path, media_type="image/svg+xml")
        return JSONResponse(status_code=404, content={"error": "og-image not found"})

    # Resolve favicon path once at startup
    _favicon_path = None
    for _fav_path in [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "landing", "favicon.svg"),
        os.path.join("/app", "docs", "landing", "favicon.svg"),
    ]:
        if os.path.exists(_fav_path):
            _favicon_path = _fav_path
            break

    @app.get("/favicon.ico")
    def favicon_ico():
        if _favicon_path and os.path.exists(_favicon_path):
            return FileResponse(_favicon_path, media_type="image/svg+xml")
        return JSONResponse(status_code=404, content={"error": "favicon not found"})

    @app.get("/favicon.svg")
    def favicon_svg():
        if _favicon_path and os.path.exists(_favicon_path):
            return FileResponse(_favicon_path, media_type="image/svg+xml")
        return JSONResponse(status_code=404, content={"error": "favicon not found"})

    @app.get("/robots.txt")
    def robots_txt():
        return Response(
            content=(
                "User-agent: *\n"
                "Allow: /\n"
                "Disallow: /v1/\n"
                "Disallow: /docs\n"
                "Disallow: /redoc\n"
                "Disallow: /health\n"
                "Disallow: /automate/\n"
                "Sitemap: https://www.governlayer.ai/sitemap.xml\n"
            ),
            media_type="text/plain",
        )

    @app.get("/sitemap.xml")
    def sitemap_xml():
        return Response(
            content=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemapschemas.org/sitemap/0.9">\n'
                '  <url><loc>https://www.governlayer.ai/</loc><priority>1.0</priority><changefreq>weekly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/trust</loc><priority>0.8</priority><changefreq>monthly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/demo</loc><priority>0.9</priority><changefreq>monthly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/terms</loc><priority>0.3</priority><changefreq>yearly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/privacy</loc><priority>0.3</priority><changefreq>yearly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/dashboard</loc><priority>0.7</priority><changefreq>weekly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/signup</loc><priority>0.8</priority><changefreq>monthly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/changelog</loc><priority>0.5</priority><changefreq>monthly</changefreq></url>\n'
                '  <url><loc>https://www.governlayer.ai/blog</loc><priority>0.7</priority><changefreq>weekly</changefreq></url>\n'
                '</urlset>\n'
            ),
            media_type="application/xml",
        )

    @app.get("/")
    def root(request: Request):
        # Serve landing page to browsers, JSON to API clients
        accept = request.headers.get("accept", "")
        if _landing_html and "text/html" in accept:
            return HTMLResponse(_landing_html)
        return {
            "name": "GovernLayer",
            "tagline": "The Governance Layer for Agentic AI",
            "version": settings.policy_version,
            "status": "operational",
            "frameworks": len(FRAMEWORKS),
            "docs": "/docs",
            "quickstart": {
                "1_create_org": "POST /v1/enterprise/orgs",
                "2_get_api_key": "POST /v1/enterprise/orgs/{slug}/api-keys",
                "3_govern": "POST /v1/govern",
                "4_scan": "POST /v1/scan",
            },
            "endpoints": {
                "enterprise": "/v1/govern, /v1/risk, /v1/drift, /v1/scan, /v1/audit/{system}",
                "management": "/v1/enterprise/orgs, /v1/enterprise/orgs/{slug}/api-keys",
                "legacy": "/govern, /audit, /risk-score, /drift",
            },
        }

    @app.get("/api")
    def api_status():
        """JSON API status — always returns JSON regardless of Accept header."""
        return {
            "name": "GovernLayer",
            "tagline": "The Governance Layer for Agentic AI",
            "version": settings.policy_version,
            "status": "operational",
            "frameworks": len(FRAMEWORKS),
            "docs": "/docs",
        }

    @app.get("/frameworks")
    def list_frameworks():
        return {"total": len(FRAMEWORKS), "frameworks": FRAMEWORKS}

    @app.post("/drift")
    def detect_drift(request: DriftRequest, email: str = Depends(verify_token)):
        from src.drift.detection import analyze_reasoning
        return analyze_reasoning(
            reasoning_trace=request.reasoning_trace,
            use_case=request.use_case,
            threshold=request.threshold,
        )

    def _send_contact_email(entry: dict):
        """Fire-and-forget email notification via Resend API."""
        api_key = settings.resend_api_key
        if not api_key:
            logger.warning("RESEND_API_KEY not set — skipping contact email notification")
            return

        html_body = (
            f"<h2>New {entry['form_type']} request</h2>"
            f"<p><strong>Name:</strong> {entry['name']}</p>"
            f"<p><strong>Email:</strong> {entry['email']}</p>"
            f"<p><strong>Company:</strong> {entry['company']}</p>"
            f"<p><strong>Message:</strong> {entry.get('message') or '(none)'}</p>"
            f"<p><strong>Submitted:</strong> {entry['submitted_at']}</p>"
        )

        email_payload = {
            "from": "GovernLayer <noreply@governlayer.ai>",
            "to": ["founders@governlayer.ai"],
            "subject": f"New {entry['form_type']} request from {entry['name']} at {entry['company']}",
            "html": html_body,
        }

        try:
            import httpx
            with httpx.Client(timeout=10) as client:
                resp = client.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=email_payload,
                )
            if resp.status_code >= 400:
                logger.error("Resend API error %s: %s", resp.status_code, resp.text)
            else:
                logger.info("Contact email sent via Resend for %s", entry['email'])
        except ImportError:
            # httpx not available — fall back to urllib
            try:
                import urllib.request
                req = urllib.request.Request(
                    "https://api.resend.com/emails",
                    data=json.dumps(email_payload).encode(),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    logger.info("Contact email sent via Resend (urllib) for %s", entry['email'])
            except Exception as exc:
                logger.error("Failed to send contact email via urllib: %s", exc)
        except Exception as exc:
            logger.error("Failed to send contact email via Resend: %s", exc)

    @app.post("/contact")
    def contact_submit(payload: ContactRequest):
        """Accept a contact/demo request form submission. No auth required."""
        # Validate email format
        if not _EMAIL_RE.match(payload.email):
            return JSONResponse(
                status_code=422,
                content={"status": "error", "message": "Invalid email address"},
            )

        entry = {
            "name": payload.name,
            "email": payload.email,
            "company": payload.company,
            "message": payload.message,
            "form_type": payload.form_type,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }

        # Append to JSON file
        try:
            if CONTACTS_FILE.exists():
                contacts = json.loads(CONTACTS_FILE.read_text())
            else:
                contacts = []
            contacts.append(entry)
            CONTACTS_FILE.write_text(json.dumps(contacts, indent=2))
        except Exception as exc:
            logger.error("Failed to write contact to %s: %s", CONTACTS_FILE, exc)

        logger.info(
            "Contact form submission: name=%s email=%s company=%s form_type=%s",
            payload.name, payload.email, payload.company, payload.form_type,
        )

        # Send email notification (fire-and-forget — never blocks the response)
        _send_contact_email(entry)

        return {"status": "ok", "message": "We'll be in touch within 24 hours"}

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)
