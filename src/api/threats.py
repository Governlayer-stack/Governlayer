from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from src.api.deps import get_llm, get_search
from src.models.schemas import IncidentRequest, JurisdictionRequest, ThreatRequest
from src.security.auth import verify_token

router = APIRouter(tags=["threats"])


def _safe_llm_invoke(llm, prompt: str) -> str:
    """Invoke LLM with graceful error handling for payment/quota issues."""
    try:
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        err_str = str(e).lower()
        if "402" in err_str or "payment" in err_str or "credits" in err_str or "quota" in err_str:
            raise HTTPException(status_code=503, detail="LLM service temporarily unavailable — provider quota exceeded. Please try again later.")
        if "401" in err_str or "unauthorized" in err_str or "invalid api key" in err_str:
            raise HTTPException(status_code=503, detail="LLM service configuration error. Please contact support.")
        raise HTTPException(status_code=503, detail=f"LLM service error: {type(e).__name__}")


@router.post("/threats")
def analyze_threats(request: ThreatRequest, email: str = Depends(verify_token)):
    search = get_search()
    llm = get_llm()
    search_context = ""
    if search:
        try:
            search_context = f" Search results: {search.run(f'MITRE ATLAS AI attacks {request.system_type} 2025')}"
        except Exception:
            pass
    content = _safe_llm_invoke(
        llm,
        f"Analyze AI threats for {request.system_type} in {request.deployment_context}."
        f"{search_context} List top threats and security controls."
    )
    return {
        "system_type": request.system_type,
        "threats": content,
        "analyzed_at": datetime.utcnow().isoformat(),
    }


@router.post("/incident-response")
def incident_response(request: IncidentRequest, email: str = Depends(verify_token)):
    llm = get_llm()
    content = _safe_llm_invoke(
        llm,
        f"Generate AI incident response plan for {request.incident_type} on {request.system_name} "
        f"affecting {request.affected_users} users in {request.industry}."
    )
    return {"incident_type": request.incident_type, "system": request.system_name, "response_plan": content}


@router.post("/jurisdiction")
def jurisdiction_map(request: JurisdictionRequest, email: str = Depends(verify_token)):
    llm = get_llm()
    content = _safe_llm_invoke(
        llm,
        f"Map AI regulations for {request.countries} in {request.industry} for {request.ai_system_type}. "
        f"List all laws, deadlines and requirements."
    )
    return {"countries": request.countries, "regulations": content}


@router.get("/deadlines")
def compliance_deadlines(region: str = "global", email: str = Depends(verify_token)):
    search = get_search()
    llm = get_llm()
    search_context = ""
    if search:
        try:
            search_context = f": {search.run(f'AI regulation compliance deadline 2025 2026 {region}')}"
        except Exception:
            pass
    content = _safe_llm_invoke(llm, f"List upcoming AI compliance deadlines for {region}{search_context}")
    return {"region": region, "deadlines": content}
