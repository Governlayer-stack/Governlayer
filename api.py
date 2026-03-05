from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from langchain_groq import ChatGroq
from langchain_community.tools import DuckDuckGoSearchRun
from dotenv import load_dotenv
from datetime import datetime, timedelta
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from database import get_db, AuditRecord, RiskScoreRecord, User, compute_hash, get_last_hash, create_tables
from drift_detection import analyze_reasoning
import bcrypt
import uuid
import os

load_dotenv()

app = FastAPI(title="GovernLayer API", description="The worlds most comprehensive AI Governance platform", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

llm = ChatGroq(model="llama-3.3-70b-versatile")
search = DuckDuckGoSearchRun()
SECRET_KEY = "governlayer-secret-key"
ALGORITHM = "HS256"
security = HTTPBearer()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password[:72].encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password[:72].encode(), hashed.encode())

def create_token(email: str):
    expire = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

class UserRegister(BaseModel):
    email: str
    password: str
    company: str

class UserLogin(BaseModel):
    email: str
    password: str

class AuditRequest(BaseModel):
    system_name: str
    system_description: str
    industry: str
    frameworks: Optional[str] = "NIST_AI_RMF,EU_AI_ACT,ISO_42001"

class DriftRequest(BaseModel):
    reasoning_trace: str
    use_case: str = "general"
    threshold: float = 0.3

class GovernRequest(BaseModel):
    system_name: str
    use_case: str
    reasoning_trace: str
    ai_decision: str
    ai_confidence: float = 0.85
    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = False
    has_bias_testing: bool = False

class RiskScoreRequest(BaseModel):
    system_name: str
    handles_personal_data: bool
    makes_autonomous_decisions: bool
    used_in_critical_infrastructure: bool
    has_human_oversight: bool
    is_explainable: bool
    has_bias_testing: bool

class ThreatRequest(BaseModel):
    system_type: str
    deployment_context: str

class JurisdictionRequest(BaseModel):
    countries: str
    industry: str
    ai_system_type: str

class IncidentRequest(BaseModel):
    incident_type: str
    system_name: str
    affected_users: str
    industry: str

@app.on_event("startup")
def startup():
    create_tables()

@app.get("/")
def root():
    return {"name": "GovernLayer API", "version": "1.0.0", "status": "operational", "frameworks": 25, "components": ["policy_engine", "drift_detection", "risk_scoring", "decision_controller", "audit_ledger"]}

@app.post("/auth/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(email=user.email, password_hash=hash_password(user.password), company=user.company)
    db.add(new_user)
    db.commit()
    token = create_token(user.email)
    return {"message": f"Welcome to GovernLayer {user.company}", "token": token, "email": user.email}

@app.post("/auth/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_token(user.email), "email": user.email}

@app.get("/frameworks")
def list_frameworks(email: str = Depends(verify_token)):
    frameworks = ["NIST_AI_RMF","EU_AI_ACT","ISO_42001","MITRE_ATLAS","OWASP_AI","SOC2","GDPR","CCPA","HIPAA","IEEE_ETHICS","OECD_AI","UNESCO_AI","SINGAPORE_AI","UK_AI","CANADA_AIDA","CHINA_AI","COBIT","ITIL","ISO_27001","NIST_CSF","ZERO_TRUST","CIS_CONTROLS","FAIR_RISK","CSA_AI","US_EO_AI"]
    return {"total": 25, "frameworks": frameworks}

@app.post("/drift")
def detect_drift(request: DriftRequest, email: str = Depends(verify_token)):
    result = analyze_reasoning(
        reasoning_trace=request.reasoning_trace,
        use_case=request.use_case,
        threshold=request.threshold
    )
    return {
        "analyzed_by": email,
        **result
    }

@app.post("/govern")
def govern_decision(request: GovernRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    drift_result = analyze_reasoning(
        reasoning_trace=request.reasoning_trace,
        use_case=request.use_case
    )
    scores = {
        "Privacy": 100 if not request.handles_personal_data else 40,
        "Autonomy_Risk": 100 if not request.makes_autonomous_decisions else 30,
        "Infrastructure_Risk": 100 if not request.used_in_critical_infrastructure else 25,
        "Oversight": 100 if request.has_human_oversight else 20,
        "Transparency": 100 if request.is_explainable else 30,
        "Fairness": 100 if request.has_bias_testing else 25
    }
    overall_risk = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall_risk >= 80 else "MEDIUM" if overall_risk >= 50 else "HIGH"
    if drift_result["vetoed"]:
        governance_action = "BLOCK"
        reason = f"BLOCKED: Behavioral drift detected. D_c={drift_result['drift_coefficient']} exceeds threshold τ={drift_result['threshold']}. {drift_result['explanation']}"
    elif risk_level == "HIGH":
        governance_action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: High risk score {round(overall_risk)}/100. Requires human review before execution."
    elif risk_level == "MEDIUM" and drift_result["semantic_risk_flags"] > 0:
        governance_action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: Medium risk with {drift_result['semantic_risk_flags']} semantic risk flags detected."
    else:
        governance_action = "APPROVE"
        reason = f"APPROVED: Risk score {round(overall_risk)}/100. Drift coefficient {drift_result['drift_coefficient']} within safe boundaries."
    decision_id = str(uuid.uuid4())
    previous_hash = get_last_hash(db)
    record_data = {
        "decision_id": decision_id,
        "system_name": request.system_name,
        "governance_action": governance_action,
        "drift_coefficient": drift_result["drift_coefficient"],
        "risk_score": overall_risk,
        "policy_version": "1.0.0",
        "created_at": datetime.utcnow().isoformat()
    }
    current_hash = compute_hash({**record_data, "previous_hash": previous_hash})
    audit = AuditRecord(
        decision_id=decision_id,
        system_name=request.system_name,
        industry=request.use_case,
        audited_by=email,
        frameworks_audited="NIST_AI_RMF,EU_AI_ACT,ISO_42001",
        results=reason,
        risk_score=overall_risk,
        risk_level=risk_level,
        governance_action=governance_action,
        policy_version="1.0.0",
        previous_hash=previous_hash,
        current_hash=current_hash
    )
    db.add(audit)
    db.commit()
    return {
        "decision_id": decision_id,
        "system": request.system_name,
        "governance_action": governance_action,
        "reason": reason,
        "drift_analysis": drift_result,
        "risk_score": round(overall_risk),
        "risk_level": risk_level,
        "dimension_scores": scores,
        "current_hash": current_hash,
        "policy_version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/audit")
def audit_system(request: AuditRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    prompt = f"You are a world class AI governance auditor. Audit this system: {request.system_name} in {request.industry}. Description: {request.system_description}. Frameworks: {request.frameworks}. For each framework provide compliance status, gaps and recommendations."
    response = llm.invoke(prompt)
    decision_id = str(uuid.uuid4())
    previous_hash = get_last_hash(db)
    record_data = {"decision_id": decision_id, "system_name": request.system_name, "governance_action": "AUDIT_COMPLETE", "policy_version": "1.0.0", "created_at": datetime.utcnow().isoformat()}
    current_hash = compute_hash({**record_data, "previous_hash": previous_hash})
    audit = AuditRecord(decision_id=decision_id, system_name=request.system_name, industry=request.industry, audited_by=email, frameworks_audited=request.frameworks, results=response.content, governance_action="AUDIT_COMPLETE", policy_version="1.0.0", previous_hash=previous_hash, current_hash=current_hash)
    db.add(audit)
    db.commit()
    return {"decision_id": decision_id, "system": request.system_name, "industry": request.industry, "audit_date": datetime.utcnow().isoformat(), "audited_by": email, "governance_action": "AUDIT_COMPLETE", "current_hash": current_hash, "previous_hash": previous_hash, "policy_version": "1.0.0", "results": response.content}

@app.post("/risk-score")
def risk_score(request: RiskScoreRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    scores = {"Privacy": 100 if not request.handles_personal_data else 40, "Autonomy_Risk": 100 if not request.makes_autonomous_decisions else 30, "Infrastructure_Risk": 100 if not request.used_in_critical_infrastructure else 25, "Oversight": 100 if request.has_human_oversight else 20, "Transparency": 100 if request.is_explainable else 30, "Fairness": 100 if request.has_bias_testing else 25}
    overall = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall >= 80 else "MEDIUM" if overall >= 50 else "HIGH"
    record = RiskScoreRecord(system_name=request.system_name, overall_score=round(overall), risk_level=risk_level, privacy_score=scores["Privacy"], autonomy_score=scores["Autonomy_Risk"], infrastructure_score=scores["Infrastructure_Risk"], oversight_score=scores["Oversight"], transparency_score=scores["Transparency"], fairness_score=scores["Fairness"], scored_by=email)
    db.add(record)
    db.commit()
    return {"system": request.system_name, "overall_score": round(overall), "risk_level": risk_level, "dimension_scores": scores, "scored_by": email, "scored_at": datetime.utcnow().isoformat()}

@app.get("/audit-history")
def audit_history(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    records = db.query(AuditRecord).filter(AuditRecord.audited_by == email).order_by(AuditRecord.created_at.desc()).all()
    return {"total": len(records), "audits": [{"decision_id": r.decision_id, "system_name": r.system_name, "governance_action": r.governance_action, "risk_score": r.risk_score, "risk_level": r.risk_level, "current_hash": r.current_hash, "created_at": r.created_at.isoformat()} for r in records]}

@app.get("/ledger")
def view_ledger(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    records = db.query(AuditRecord).order_by(AuditRecord.id.asc()).all()
    return {"total_records": len(records), "ledger": [{"id": r.id, "decision_id": r.decision_id, "system_name": r.system_name, "governance_action": r.governance_action, "risk_score": r.risk_score, "risk_level": r.risk_level, "policy_version": r.policy_version, "previous_hash": r.previous_hash, "current_hash": r.current_hash, "created_at": r.created_at.isoformat()} for r in records]}

@app.post("/threats")
def analyze_threats(request: ThreatRequest, email: str = Depends(verify_token)):
    results = search.run(f"MITRE ATLAS AI attacks {request.system_type} 2025")
    response = llm.invoke(f"Analyze AI threats for {request.system_type} in {request.deployment_context}. Search results: {results}. List top threats and security controls.")
    return {"system_type": request.system_type, "threats": response.content, "analyzed_at": datetime.utcnow().isoformat()}

@app.post("/incident-response")
def incident_response(request: IncidentRequest, email: str = Depends(verify_token)):
    response = llm.invoke(f"Generate AI incident response plan for {request.incident_type} on {request.system_name} affecting {request.affected_users} users in {request.industry}.")
    return {"incident_type": request.incident_type, "system": request.system_name, "response_plan": response.content}

@app.post("/jurisdiction")
def jurisdiction_map(request: JurisdictionRequest, email: str = Depends(verify_token)):
    response = llm.invoke(f"Map AI regulations for {request.countries} in {request.industry} for {request.ai_system_type}. List all laws, deadlines and requirements.")
    return {"countries": request.countries, "regulations": response.content}

@app.get("/deadlines")
def compliance_deadlines(region: str = "global", email: str = Depends(verify_token)):
    results = search.run(f"AI regulation compliance deadline 2025 2026 {region}")
    response = llm.invoke(f"List upcoming AI compliance deadlines for {region}: {results}")
    return {"region": region, "deadlines": response.content}

if __name__ == "__main__":
    import uvicorn
    print("Starting GovernLayer API with Drift Detection...")
    print("Components: Policy Engine + Drift Detection + Risk Scoring + Ledger")
    print("Docs at: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
