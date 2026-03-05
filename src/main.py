"""GovernLayer API — application factory."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config import get_settings
from src.models.database import create_tables
from src.api import auth, governance, audit, risk, ledger, threats

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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Tighten for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(auth.router)
    app.include_router(governance.router)
    app.include_router(audit.router)
    app.include_router(risk.router)
    app.include_router(ledger.router)
    app.include_router(threats.router)

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
            ],
        }

    @app.get("/frameworks")
    def list_frameworks():
        return {"total": len(FRAMEWORKS), "frameworks": FRAMEWORKS}

    @app.post("/drift")
    def detect_drift(request: dict):
        from src.drift.detection import analyze_reasoning
        return analyze_reasoning(
            reasoning_trace=request.get("reasoning_trace", ""),
            use_case=request.get("use_case", "general"),
            threshold=request.get("threshold", 0.3),
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)
