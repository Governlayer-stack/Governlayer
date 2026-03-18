"""GovernLayer API — application factory."""

import logging
import os

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text as sa_text
from starlette.middleware.base import BaseHTTPMiddleware

from src.api import (
    achonye, agent_registry, analytics, analytics_usage, audit, auth, automation,
    billing, dashboard, enterprise, enterprise_features, governance, growth,
    incidents, integrations, knowledge_graph, ledger, mfa, policies, rbac_views,
    registry, reports, risk, threats, v1,
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
            RegisteredModel(name="loan-approval-v3", version="3.2.1", framework="xgboost",
                            description="Credit risk scoring model for consumer loans",
                            owner="ml-platform@company.com", use_case="Credit decisioning",
                            lifecycle=ModelLifecycle.PRODUCTION, governance_status="compliant", risk_score=34.0),
            RegisteredModel(name="fraud-detector", version="2.1.0", framework="pytorch",
                            description="Real-time transaction fraud detection",
                            owner="fraud-team@company.com", use_case="Fraud prevention",
                            lifecycle=ModelLifecycle.PRODUCTION, governance_status="compliant", risk_score=45.0),
            RegisteredModel(name="content-moderator", version="1.5.0", framework="transformers",
                            description="User-generated content safety classifier",
                            owner="trust-safety@company.com", use_case="Content moderation",
                            lifecycle=ModelLifecycle.STAGING, governance_status="pending", risk_score=62.0),
            RegisteredModel(name="resume-screener", version="0.9.0", framework="sklearn",
                            description="Candidate resume ranking model",
                            owner="hr-tech@company.com", use_case="Hiring automation",
                            lifecycle=ModelLifecycle.DEVELOPMENT, governance_status="non_compliant", risk_score=78.0),
            RegisteredModel(name="chatbot-support", version="4.0.0", framework="openai",
                            description="Customer support conversational AI",
                            owner="cx-team@company.com", use_case="Customer support",
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
        return response

FRAMEWORKS = [
    "NIST_AI_RMF", "EU_AI_ACT", "ISO_42001", "ISO_27001", "NIS2", "DORA",
    "MITRE_ATLAS", "OWASP_AI", "SOC2", "GDPR", "CCPA", "HIPAA",
    "IEEE_ETHICS", "OECD_AI", "NIST_CSF", "UNESCO_AI", "SINGAPORE_AI",
    "UK_AI", "CANADA_AIDA", "CHINA_AI", "COBIT", "ITIL",
    "ZERO_TRUST", "CIS_CONTROLS", "FAIR_RISK", "CSA_AI", "US_EO_AI",
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
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(UsageMeteringMiddleware)

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

    @app.on_event("startup")
    def startup():
        create_tables()
        _ensure_schema_columns()
        _seed_demo_data()

    def _ensure_schema_columns():
        """Add columns that create_tables() won't add to existing tables."""
        from src.models.database import SessionLocal
        db = SessionLocal()
        try:
            for stmt in [
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(64)",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires_at TIMESTAMP",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(32)",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_codes TEXT",
            ]:
                db.execute(sa_text(stmt))
            db.commit()
        except Exception as e:
            logging.getLogger(__name__).warning(f"Schema migration skip: {e}")
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

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)
