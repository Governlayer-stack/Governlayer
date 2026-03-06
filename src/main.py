"""GovernLayer API — application factory."""

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from src.config import get_settings
from src.models.database import create_tables
from src.models.schemas import DriftRequest
from src.security.auth import verify_token
from src.api import auth, governance, audit, risk, ledger, threats, achonye, automation


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
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
        description="AI Governance Control Plane",
        version=settings.policy_version,
    )

    allowed_origins = settings.cors_origins.split(",") if settings.cors_origins else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)

    # Register routers
    app.include_router(auth.router)
    app.include_router(governance.router)
    app.include_router(audit.router)
    app.include_router(risk.router)
    app.include_router(ledger.router)
    app.include_router(threats.router)
    app.include_router(achonye.router)
    app.include_router(automation.router)

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
            "components": [
                "policy_engine", "drift_detection", "risk_scoring",
                "decision_controller", "audit_ledger", "agent_orchestrator",
                "achonye_multi_llm",
            ],
            "achonye": "Multi-LLM orchestration active",
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
