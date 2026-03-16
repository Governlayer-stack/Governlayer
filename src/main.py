"""GovernLayer API — application factory."""

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from src.api import achonye, audit, auth, automation, billing, enterprise, governance, ledger, risk, threats, v1
from src.config import get_settings
from src.models.database import create_tables
from src.models.schemas import DriftRequest
from src.security.auth import verify_token


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
    "NIST_AI_RMF", "EU_AI_ACT", "ISO_42001", "MITRE_ATLAS", "OWASP_AI",
    "SOC2", "GDPR", "CCPA", "HIPAA", "IEEE_ETHICS", "OECD_AI", "UNESCO_AI",
    "SINGAPORE_AI", "UK_AI", "CANADA_AIDA", "CHINA_AI", "COBIT", "ITIL",
    "ISO_27001", "NIST_CSF", "ZERO_TRUST", "CIS_CONTROLS", "FAIR_RISK",
    "CSA_AI", "US_EO_AI",
]


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="GovernLayer API",
        description=(
            "AI Governance Control Plane — compliance auditing, behavioral drift detection, "
            "risk scoring, and immutable audit ledger for enterprise AI systems.\n\n"
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

    @app.on_event("startup")
    def startup():
        create_tables()

    @app.get("/")
    def root():
        return {
            "name": "GovernLayer API",
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
