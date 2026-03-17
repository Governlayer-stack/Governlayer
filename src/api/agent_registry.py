"""Agent Registry API — discover, register, and govern AI agents + Shadow AI detection."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.models.database import SessionLocal
from src.models.agents import AIAgent, AgentCard, ShadowAIDetection, AgentStatus, AgentType, DiscoverySource

router = APIRouter(prefix="/v1/agents", tags=["Agent Registry"])


class AgentCreate(BaseModel):
    name: str
    agent_type: str = "autonomous"
    description: Optional[str] = None
    owner: Optional[str] = None
    team: Optional[str] = None
    purpose: Optional[str] = None
    tools: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    guardrails: List[str] = Field(default_factory=list)
    autonomy_level: int = 1
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    model_id: Optional[int] = None
    risk_tier: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentCardCreate(BaseModel):
    intended_use: Optional[str] = None
    limitations: Optional[str] = None
    ethical_considerations: Optional[str] = None
    interaction_patterns: List[str] = Field(default_factory=list)
    failure_modes: List[str] = Field(default_factory=list)
    escalation_policy: Optional[str] = None
    data_retention: Optional[str] = None
    compliance_notes: Optional[str] = None


class AgentApproval(BaseModel):
    action: str
    approved_by: Optional[str] = None
    reason: Optional[str] = None


class ShadowScanRequest(BaseModel):
    scan_type: str = "api_patterns"
    targets: List[str] = Field(default_factory=list)


def _agent_dict(a):
    return {
        "id": a.id, "name": a.name,
        "agent_type": a.agent_type.value if a.agent_type else None,
        "status": a.status.value if a.status else None,
        "description": a.description, "owner": a.owner, "team": a.team,
        "purpose": a.purpose, "tools": a.tools, "data_sources": a.data_sources,
        "permissions": a.permissions, "guardrails": a.guardrails,
        "autonomy_level": a.autonomy_level,
        "model_provider": a.model_provider, "model_name": a.model_name,
        "risk_tier": a.risk_tier, "risk_score": a.risk_score,
        "governance_status": a.governance_status, "is_shadow": a.is_shadow,
        "discovery_source": a.discovery_source.value if a.discovery_source else None,
        "tags": a.tags, "dependencies": a.dependencies,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


@router.post("")
def register_agent(data: AgentCreate):
    """Register an AI agent in the governance registry."""
    db = SessionLocal()
    try:
        agent = AIAgent(
            name=data.name,
            agent_type=AgentType(data.agent_type) if data.agent_type else AgentType.AUTONOMOUS,
            description=data.description, owner=data.owner, team=data.team,
            purpose=data.purpose, tools=data.tools, data_sources=data.data_sources,
            permissions=data.permissions, guardrails=data.guardrails,
            autonomy_level=data.autonomy_level, model_provider=data.model_provider,
            model_name=data.model_name, model_id=data.model_id, risk_tier=data.risk_tier,
            tags=data.tags, metadata_=data.metadata,
            discovery_source=DiscoverySource.MANUAL, is_shadow=False,
            first_seen_at=datetime.utcnow(),
        )
        db.add(agent)
        db.commit()
        db.refresh(agent)
        return _agent_dict(agent)
    finally:
        db.close()


@router.get("")
def list_agents(status: Optional[str] = None, agent_type: Optional[str] = None,
                is_shadow: Optional[bool] = None, team: Optional[str] = None):
    """List all registered agents with optional filters."""
    db = SessionLocal()
    try:
        query = db.query(AIAgent)
        if status:
            query = query.filter(AIAgent.status == status)
        if agent_type:
            query = query.filter(AIAgent.agent_type == agent_type)
        if is_shadow is not None:
            query = query.filter(AIAgent.is_shadow == is_shadow)
        if team:
            query = query.filter(AIAgent.team == team)
        agents = query.order_by(AIAgent.created_at.desc()).all()
        return {
            "total": len(agents),
            "approved": sum(1 for a in agents if a.status == AgentStatus.APPROVED),
            "shadow_detected": sum(1 for a in agents if a.is_shadow),
            "agents": [_agent_dict(a) for a in agents],
        }
    finally:
        db.close()


@router.get("/{agent_id}")
def get_agent(agent_id: int):
    """Get detailed agent information including agent card."""
    db = SessionLocal()
    try:
        agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        result = _agent_dict(agent)
        if agent.card:
            result["card"] = {
                "intended_use": agent.card.intended_use,
                "limitations": agent.card.limitations,
                "ethical_considerations": agent.card.ethical_considerations,
                "interaction_patterns": agent.card.interaction_patterns,
                "failure_modes": agent.card.failure_modes,
                "escalation_policy": agent.card.escalation_policy,
                "data_retention": agent.card.data_retention,
            }
        return result
    finally:
        db.close()


@router.post("/{agent_id}/card")
def create_agent_card(agent_id: int, data: AgentCardCreate):
    """Create an agent card for transparency documentation."""
    db = SessionLocal()
    try:
        agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        existing = db.query(AgentCard).filter(AgentCard.agent_id == agent_id).first()
        if existing:
            for field in ["intended_use", "limitations", "ethical_considerations", "escalation_policy", "data_retention", "compliance_notes"]:
                val = getattr(data, field, None)
                if val:
                    setattr(existing, field, val)
            if data.interaction_patterns:
                existing.interaction_patterns = data.interaction_patterns
            if data.failure_modes:
                existing.failure_modes = data.failure_modes
            existing.updated_at = datetime.utcnow()
            db.commit()
            return {"id": existing.id, "agent_id": agent_id, "updated": True}
        card = AgentCard(agent_id=agent_id, **data.model_dump())
        db.add(card)
        db.commit()
        db.refresh(card)
        return {"id": card.id, "agent_id": agent_id, "created": True}
    finally:
        db.close()


@router.post("/{agent_id}/governance")
def update_agent_governance(agent_id: int, data: AgentApproval):
    """Approve, reject, suspend, or activate an agent."""
    action_map = {
        "approve": AgentStatus.APPROVED, "reject": AgentStatus.REJECTED,
        "suspend": AgentStatus.SUSPENDED, "activate": AgentStatus.ACTIVE,
        "review": AgentStatus.UNDER_REVIEW,
    }
    if data.action not in action_map:
        raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of: {list(action_map.keys())}")

    db = SessionLocal()
    try:
        agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        agent.status = action_map[data.action]
        if data.action == "approve":
            agent.approved_by = data.approved_by
            agent.approved_at = datetime.utcnow()
            agent.governance_status = "compliant"
        elif data.action == "reject":
            agent.governance_status = "non_compliant"
        elif data.action == "suspend":
            agent.governance_status = "suspended"
        agent.updated_at = datetime.utcnow()
        db.commit()
        return {"id": agent.id, "name": agent.name, "status": agent.status.value, "governance_status": agent.governance_status}
    finally:
        db.close()


@router.get("/{agent_id}/dependencies")
def get_agent_dependencies(agent_id: int):
    """Get the dependency graph for an agent."""
    db = SessionLocal()
    try:
        agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        dep_agents = []
        for dep in (agent.dependencies or []):
            dep_id = dep.get("agent_id")
            if dep_id:
                dep_agent = db.query(AIAgent).filter(AIAgent.id == dep_id).first()
                if dep_agent:
                    dep_agents.append({"id": dep_agent.id, "name": dep_agent.name, "type": dep.get("type", "unknown"), "status": dep_agent.status.value if dep_agent.status else None})
        return {
            "agent_id": agent.id, "agent_name": agent.name,
            "dependencies": dep_agents,
            "upstream_services": agent.upstream_services or [],
            "downstream_services": agent.downstream_services or [],
            "tools": agent.tools or [], "data_sources": agent.data_sources or [],
        }
    finally:
        db.close()


# --- Shadow AI Discovery ---

SHADOW_AI_PATTERNS = {
    "openai": {"pattern": "api.openai.com", "provider": "OpenAI", "severity": "high"},
    "anthropic": {"pattern": "api.anthropic.com", "provider": "Anthropic", "severity": "high"},
    "huggingface": {"pattern": "api-inference.huggingface.co", "provider": "HuggingFace", "severity": "medium"},
    "cohere": {"pattern": "api.cohere.ai", "provider": "Cohere", "severity": "medium"},
    "replicate": {"pattern": "api.replicate.com", "provider": "Replicate", "severity": "medium"},
    "google_ai": {"pattern": "generativelanguage.googleapis.com", "provider": "Google AI", "severity": "high"},
    "azure_openai": {"pattern": "openai.azure.com", "provider": "Azure OpenAI", "severity": "high"},
    "bedrock": {"pattern": "bedrock-runtime", "provider": "AWS Bedrock", "severity": "high"},
    "groq": {"pattern": "api.groq.com", "provider": "Groq", "severity": "medium"},
    "mistral": {"pattern": "api.mistral.ai", "provider": "Mistral", "severity": "medium"},
    "together": {"pattern": "api.together.xyz", "provider": "Together AI", "severity": "medium"},
    "ollama": {"pattern": "localhost:11434", "provider": "Ollama (Local)", "severity": "low"},
    "langchain": {"pattern": "smith.langchain.com", "provider": "LangChain", "severity": "medium"},
    "crewai": {"pattern": "crewai", "provider": "CrewAI", "severity": "medium"},
    "autogen": {"pattern": "autogen", "provider": "AutoGen", "severity": "medium"},
}


@router.post("/discovery/scan")
def scan_for_shadow_ai(data: ShadowScanRequest):
    """Scan for unauthorized/unregistered AI usage (Shadow AI detection)."""
    db = SessionLocal()
    try:
        detections = []
        for target in data.targets:
            target_lower = target.lower()
            for pid, info in SHADOW_AI_PATTERNS.items():
                if info["pattern"].lower() in target_lower:
                    existing = db.query(AIAgent).filter(AIAgent.model_provider == info["provider"], AIAgent.is_shadow == False).first()
                    if not existing:
                        det = ShadowAIDetection(
                            detection_type="api_pattern", source=data.scan_type,
                            description=f"Unregistered {info['provider']} AI usage detected",
                            evidence={"target": target, "pattern": info["pattern"]},
                            severity=info["severity"], detected_service=info["provider"], detected_model=pid,
                        )
                        db.add(det)
                        detections.append({"provider": info["provider"], "severity": info["severity"], "source": target, "registered": False})
                    else:
                        detections.append({"provider": info["provider"], "severity": "info", "registered": True, "agent_id": existing.id})
        db.commit()
        unregistered = [d for d in detections if not d.get("registered")]
        return {
            "scan_type": data.scan_type, "targets_scanned": len(data.targets),
            "total_detections": len(detections), "unregistered_ai": len(unregistered),
            "risk_level": "critical" if any(d["severity"] == "high" for d in unregistered) else "medium" if unregistered else "safe",
            "detections": detections,
            "recommendation": f"Found {len(unregistered)} unregistered AI service(s). Register via POST /v1/agents." if unregistered else "All detected AI services are governed.",
            "known_patterns": len(SHADOW_AI_PATTERNS),
        }
    finally:
        db.close()


@router.get("/discovery/detections")
def list_shadow_detections(status: Optional[str] = None):
    """List all shadow AI detections."""
    db = SessionLocal()
    try:
        query = db.query(ShadowAIDetection)
        if status:
            query = query.filter(ShadowAIDetection.status == status)
        dets = query.order_by(ShadowAIDetection.created_at.desc()).all()
        return {
            "total": len(dets),
            "detections": [
                {"id": d.id, "detection_type": d.detection_type, "description": d.description,
                 "severity": d.severity, "status": d.status, "detected_service": d.detected_service,
                 "created_at": d.created_at.isoformat() if d.created_at else None}
                for d in dets
            ],
        }
    finally:
        db.close()
