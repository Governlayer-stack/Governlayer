from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.models.database import RiskScoreRecord, get_db
from src.models.schemas import RiskScoreRequest
from src.security.auth import verify_token

router = APIRouter(tags=["risk"])


@router.post("/risk-score")
def risk_score(request: RiskScoreRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    scores = {
        "Privacy": 100 if not request.handles_personal_data else 40,
        "Autonomy_Risk": 100 if not request.makes_autonomous_decisions else 30,
        "Infrastructure_Risk": 100 if not request.used_in_critical_infrastructure else 25,
        "Oversight": 100 if request.has_human_oversight else 20,
        "Transparency": 100 if request.is_explainable else 30,
        "Fairness": 100 if request.has_bias_testing else 25,
    }
    overall = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall >= 80 else "MEDIUM" if overall >= 50 else "HIGH"

    record = RiskScoreRecord(
        system_name=request.system_name, overall_score=round(overall), risk_level=risk_level,
        privacy_score=scores["Privacy"], autonomy_score=scores["Autonomy_Risk"],
        infrastructure_score=scores["Infrastructure_Risk"], oversight_score=scores["Oversight"],
        transparency_score=scores["Transparency"], fairness_score=scores["Fairness"], scored_by=email,
    )
    db.add(record)
    db.commit()

    return {
        "system": request.system_name, "overall_score": round(overall), "risk_level": risk_level,
        "dimension_scores": scores, "scored_by": email, "scored_at": datetime.utcnow().isoformat(),
    }
