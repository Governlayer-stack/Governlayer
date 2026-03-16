from datetime import datetime

from fastapi import APIRouter, Depends

from src.api.deps import get_llm, get_search
from src.models.schemas import IncidentRequest, JurisdictionRequest, ThreatRequest
from src.security.auth import verify_token

router = APIRouter(tags=["threats"])


@router.post("/threats")
def analyze_threats(request: ThreatRequest, email: str = Depends(verify_token)):
    search = get_search()
    llm = get_llm()
    results = search.run(f"MITRE ATLAS AI attacks {request.system_type} 2025")
    response = llm.invoke(
        f"Analyze AI threats for {request.system_type} in {request.deployment_context}. "
        f"Search results: {results}. List top threats and security controls."
    )
    return {
        "system_type": request.system_type,
        "threats": response.content,
        "analyzed_at": datetime.utcnow().isoformat(),
    }


@router.post("/incident-response")
def incident_response(request: IncidentRequest, email: str = Depends(verify_token)):
    llm = get_llm()
    response = llm.invoke(
        f"Generate AI incident response plan for {request.incident_type} on {request.system_name} "
        f"affecting {request.affected_users} users in {request.industry}."
    )
    return {"incident_type": request.incident_type, "system": request.system_name, "response_plan": response.content}


@router.post("/jurisdiction")
def jurisdiction_map(request: JurisdictionRequest, email: str = Depends(verify_token)):
    llm = get_llm()
    response = llm.invoke(
        f"Map AI regulations for {request.countries} in {request.industry} for {request.ai_system_type}. "
        f"List all laws, deadlines and requirements."
    )
    return {"countries": request.countries, "regulations": response.content}


@router.get("/deadlines")
def compliance_deadlines(region: str = "global", email: str = Depends(verify_token)):
    search = get_search()
    llm = get_llm()
    results = search.run(f"AI regulation compliance deadline 2025 2026 {region}")
    response = llm.invoke(f"List upcoming AI compliance deadlines for {region}: {results}")
    return {"region": region, "deadlines": response.content}
