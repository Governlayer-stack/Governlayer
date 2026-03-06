"""GovernLayer Automation API — run the full governance pipeline in one call.

Endpoints:
  POST /automate/full-pipeline   — Run drift + risk + audit + threats + ledger
  POST /automate/scan            — Quick scan (drift + risk only, no LLM)
  GET  /automate/health          — Full system health check (all services)
  POST /automate/register-bot    — Register a service account for automation
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
import uuid

from src.models.database import get_db, AuditRecord, compute_hash, get_last_hash
from src.security.auth import verify_token, hash_password, create_token
from src.drift.detection import analyze_reasoning
from src.config import get_settings

router = APIRouter(prefix="/automate", tags=["automation"])
settings = get_settings()


class FullPipelineRequest(BaseModel):
    system_name: str = Field(..., min_length=1)
    reasoning_trace: str = Field(..., min_length=1)
    use_case: str = "general"
    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = True
    has_bias_testing: bool = False
    system_description: str = ""
    industry: str = "technology"
    frameworks: str = "NIST_AI_RMF,EU_AI_ACT,ISO_42001"
    run_audit: bool = True
    run_threats: bool = False


class QuickScanRequest(BaseModel):
    system_name: str
    reasoning_trace: str
    use_case: str = "general"
    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = True
    has_bias_testing: bool = False


class BotRegisterRequest(BaseModel):
    bot_name: str = Field(default="n8n-automation")
    password: str = Field(default="governlayer-bot-2026")


def _compute_risk_scores(req) -> dict:
    return {
        "Privacy": 100 if not req.handles_personal_data else 40,
        "Autonomy_Risk": 100 if not req.makes_autonomous_decisions else 30,
        "Infrastructure_Risk": 100 if not req.used_in_critical_infrastructure else 25,
        "Oversight": 100 if req.has_human_oversight else 20,
        "Transparency": 100 if req.is_explainable else 30,
        "Fairness": 100 if req.has_bias_testing else 25,
    }


@router.post("/register-bot")
def register_bot(req: BotRegisterRequest, db: Session = Depends(get_db)):
    """Register a service account for n8n/automation use. Returns a JWT."""
    from src.models.database import User
    email = f"{req.bot_name}@governlayer.local"
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        token = create_token(email)
        return {"message": "Bot already registered", "token": token, "email": email}
    user = User(email=email, password_hash=hash_password(req.password), company="GovernLayer Automation")
    db.add(user)
    db.commit()
    token = create_token(email)
    return {"message": "Bot registered", "token": token, "email": email}


@router.post("/full-pipeline")
def full_pipeline(req: FullPipelineRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Run the complete governance pipeline in a single call.

    Steps: drift detection -> risk scoring -> governance decision -> compliance audit -> ledger entry
    """
    started_at = datetime.utcnow()
    pipeline_id = str(uuid.uuid4())
    stages = {}

    # Stage 1: Drift Detection
    drift_result = analyze_reasoning(
        reasoning_trace=req.reasoning_trace,
        use_case=req.use_case,
    )
    stages["drift"] = {
        "vetoed": drift_result["vetoed"],
        "drift_coefficient": drift_result["drift_coefficient"],
        "semantic_risk_flags": drift_result["semantic_risk_flags"],
        "explanation": drift_result["explanation"],
    }

    # Stage 2: Risk Scoring
    scores = _compute_risk_scores(req)
    overall_risk = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall_risk >= 80 else "MEDIUM" if overall_risk >= 50 else "HIGH"
    stages["risk"] = {
        "overall_score": round(overall_risk),
        "risk_level": risk_level,
        "dimension_scores": scores,
    }

    # Stage 3: Governance Decision
    if drift_result["vetoed"]:
        action = "BLOCK"
        reason = f"BLOCKED: Behavioral drift D_c={drift_result['drift_coefficient']}"
    elif risk_level == "HIGH":
        action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: High risk {round(overall_risk)}/100"
    elif risk_level == "MEDIUM" and drift_result["semantic_risk_flags"] > 0:
        action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: Medium risk + {drift_result['semantic_risk_flags']} flags"
    else:
        action = "APPROVE"
        reason = f"APPROVED: Risk {round(overall_risk)}/100, drift {drift_result['drift_coefficient']}"
    stages["decision"] = {"action": action, "reason": reason}

    # Stage 4: Compliance Audit (optional, requires LLM)
    audit_result = None
    if req.run_audit:
        try:
            from src.api.deps import get_llm
            llm = get_llm()
            prompt = (
                f"Audit AI system '{req.system_name}' in {req.industry}. "
                f"Description: {req.system_description or req.reasoning_trace[:500]}. "
                f"Frameworks: {req.frameworks}. Risk level: {risk_level}. "
                f"Governance action: {action}. Provide compliance status and gaps."
            )
            response = llm.invoke(prompt)
            audit_result = response.content
            stages["audit"] = {"status": "complete", "frameworks": req.frameworks}
        except Exception as e:
            audit_result = f"Audit skipped: {e}"
            stages["audit"] = {"status": "skipped", "error": str(e)}
    else:
        stages["audit"] = {"status": "skipped", "reason": "not requested"}

    # Stage 5: Threat Analysis (optional, requires LLM)
    threat_result = None
    if req.run_threats:
        try:
            from src.api.deps import get_llm
            llm = get_llm()
            response = llm.invoke(
                f"Analyze AI threats for {req.system_name} ({req.use_case}). "
                f"Risk level: {risk_level}. List top 5 threats and mitigations."
            )
            threat_result = response.content
            stages["threats"] = {"status": "complete"}
        except Exception as e:
            threat_result = f"Threat analysis skipped: {e}"
            stages["threats"] = {"status": "skipped", "error": str(e)}

    # Stage 6: Ledger Entry
    decision_id = str(uuid.uuid4())
    previous_hash = get_last_hash(db)
    record_data = {
        "decision_id": decision_id,
        "system_name": req.system_name,
        "governance_action": action,
        "drift_coefficient": drift_result["drift_coefficient"],
        "risk_score": overall_risk,
        "policy_version": settings.policy_version,
        "created_at": datetime.utcnow().isoformat(),
    }
    current_hash = compute_hash({**record_data, "previous_hash": previous_hash})

    audit_record = AuditRecord(
        decision_id=decision_id, system_name=req.system_name,
        industry=req.industry, audited_by=email,
        frameworks_audited=req.frameworks,
        results=audit_result or reason,
        risk_score=overall_risk, risk_level=risk_level,
        governance_action=action, policy_version=settings.policy_version,
        previous_hash=previous_hash, current_hash=current_hash,
    )
    db.add(audit_record)
    db.commit()
    stages["ledger"] = {"decision_id": decision_id, "hash": current_hash}

    elapsed = (datetime.utcnow() - started_at).total_seconds()

    return {
        "pipeline_id": pipeline_id,
        "system": req.system_name,
        "governance_action": action,
        "reason": reason,
        "risk_score": round(overall_risk),
        "risk_level": risk_level,
        "drift_coefficient": drift_result["drift_coefficient"],
        "stages": stages,
        "audit_report": audit_result,
        "threat_report": threat_result,
        "ledger_hash": current_hash,
        "policy_version": settings.policy_version,
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/scan")
def quick_scan(req: QuickScanRequest, email: str = Depends(verify_token)):
    """Quick deterministic scan — drift + risk only. No LLM calls, instant results."""
    drift_result = analyze_reasoning(
        reasoning_trace=req.reasoning_trace,
        use_case=req.use_case,
    )
    scores = _compute_risk_scores(req)
    overall_risk = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall_risk >= 80 else "MEDIUM" if overall_risk >= 50 else "HIGH"

    if drift_result["vetoed"]:
        action = "BLOCK"
    elif risk_level == "HIGH":
        action = "ESCALATE_HUMAN"
    else:
        action = "APPROVE"

    return {
        "system": req.system_name,
        "action": action,
        "risk_score": round(overall_risk),
        "risk_level": risk_level,
        "drift_coefficient": drift_result["drift_coefficient"],
        "vetoed": drift_result["vetoed"],
        "dimension_scores": scores,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/health")
def system_health():
    """Full system health check — all services. No auth required."""
    import socket
    health = {"timestamp": datetime.utcnow().isoformat(), "services": {}}

    # GovernLayer API
    health["services"]["api"] = {"status": "up", "port": settings.port}

    # PostgreSQL
    try:
        from src.models.database import SessionLocal
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        health["services"]["database"] = {"status": "up"}
    except Exception as e:
        health["services"]["database"] = {"status": "down", "error": str(e)}

    # Redis
    try:
        s = socket.create_connection(("localhost", 6379), timeout=2)
        s.close()
        health["services"]["redis"] = {"status": "up", "port": 6379}
    except Exception:
        health["services"]["redis"] = {"status": "down"}

    # Ollama
    try:
        import urllib.request
        resp = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        import json
        data = json.loads(resp.read())
        health["services"]["ollama"] = {"status": "up", "models": len(data.get("models", []))}
    except Exception:
        health["services"]["ollama"] = {"status": "down"}

    # n8n
    try:
        s = socket.create_connection(("localhost", 5678), timeout=2)
        s.close()
        health["services"]["n8n"] = {"status": "up", "port": 5678}
    except Exception:
        health["services"]["n8n"] = {"status": "down"}

    all_up = all(svc["status"] == "up" for svc in health["services"].values())
    health["overall"] = "healthy" if all_up else "degraded"

    return health
