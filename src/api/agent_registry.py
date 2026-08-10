"""Agent Registry API — discover, register, and govern AI agents + Shadow AI detection."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.pagination import PaginationParams, paginated_response
from src.models.database import get_db, log_mutation
from src.models.agents import AIAgent, AgentCard, ShadowAIDetection, AgentStatus, AgentType, DiscoverySource
from src.security.api_key_auth import AuthContext, require_scope, verify_api_key_or_jwt

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
def register_agent(data: AgentCreate,
                   auth: AuthContext = Depends(require_scope("govern")),
                   db: Session = Depends(get_db)):
    """Register an AI agent in the governance registry."""
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
        org_id=auth.org_id,
    )
    db.add(agent)
    log_mutation(db, auth.identity, "create", "agent", details=f"Registered agent {data.name}")
    db.commit()
    db.refresh(agent)
    return _agent_dict(agent)


@router.get("")
def list_agents(status: Optional[str] = None, agent_type: Optional[str] = None,
                is_shadow: Optional[bool] = None, team: Optional[str] = None,
                pagination: PaginationParams = Depends(),
                auth: AuthContext = Depends(verify_api_key_or_jwt),
                db: Session = Depends(get_db)):
    """List all registered agents with optional filters and pagination."""
    query = db.query(AIAgent)
    if auth.org_id:
        query = query.filter(AIAgent.org_id == auth.org_id)
    if status:
        query = query.filter(AIAgent.status == status)
    if agent_type:
        query = query.filter(AIAgent.agent_type == agent_type)
    if is_shadow is not None:
        query = query.filter(AIAgent.is_shadow == is_shadow)
    if team:
        query = query.filter(AIAgent.team == team)
    total = query.count()
    approved = query.filter(AIAgent.status == AgentStatus.APPROVED).count() if total > 0 else 0
    shadow = query.filter(AIAgent.is_shadow == True).count() if total > 0 else 0
    agents = query.order_by(AIAgent.created_at.desc()).offset(pagination.offset).limit(pagination.per_page).all()
    response = paginated_response(
        [_agent_dict(a) for a in agents],
        total, pagination.page, pagination.per_page,
    )
    response["approved"] = approved
    response["shadow_detected"] = shadow
    return response


@router.get("/{agent_id}")
def get_agent(agent_id: int, auth: AuthContext = Depends(verify_api_key_or_jwt),
              db: Session = Depends(get_db)):
    """Get detailed agent information including agent card."""
    agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if auth.org_id and agent.org_id != auth.org_id:
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


@router.post("/{agent_id}/card")
def create_agent_card(agent_id: int, data: AgentCardCreate,
                      auth: AuthContext = Depends(require_scope("govern")),
                      db: Session = Depends(get_db)):
    """Create an agent card for transparency documentation."""
    agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if auth.org_id and agent.org_id != auth.org_id:
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
        log_mutation(db, auth.identity, "update", "agent_card", agent_id)
        db.commit()
        return {"id": existing.id, "agent_id": agent_id, "updated": True}
    card = AgentCard(agent_id=agent_id, **data.model_dump())
    db.add(card)
    log_mutation(db, auth.identity, "create", "agent_card", agent_id)
    db.commit()
    db.refresh(card)
    return {"id": card.id, "agent_id": agent_id, "created": True}


@router.post("/{agent_id}/governance")
def update_agent_governance(agent_id: int, data: AgentApproval,
                            auth: AuthContext = Depends(require_scope("govern")),
                            db: Session = Depends(get_db)):
    """Approve, reject, suspend, or activate an agent."""
    action_map = {
        "approve": AgentStatus.APPROVED, "reject": AgentStatus.REJECTED,
        "suspend": AgentStatus.SUSPENDED, "activate": AgentStatus.ACTIVE,
        "review": AgentStatus.UNDER_REVIEW,
    }
    if data.action not in action_map:
        raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of: {list(action_map.keys())}")

    agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if auth.org_id and agent.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    old_status = agent.status.value if agent.status else "unknown"
    agent.status = action_map[data.action]
    if data.action == "approve":
        agent.approved_by = data.approved_by or auth.identity
        agent.approved_at = datetime.utcnow()
        agent.governance_status = "compliant"
    elif data.action == "reject":
        agent.governance_status = "non_compliant"
    elif data.action == "suspend":
        agent.governance_status = "suspended"
    agent.updated_at = datetime.utcnow()
    log_mutation(db, auth.identity, "update", "agent", agent_id,
                 f"Governance action: {data.action} (was {old_status})")
    db.commit()
    return {"id": agent.id, "name": agent.name, "status": agent.status.value, "governance_status": agent.governance_status}


class KillRequest(BaseModel):
    """Kill-switch payload — SR 26-2 §V.3 requires immediate, cooperative-independent termination."""
    reason: str = Field(..., min_length=1, max_length=1000,
                        description="Documented reason for termination (goes on the ledger).")
    kill_source: str = Field(default="operator",
                             description="Who or what triggered the kill: operator | auto_guardrail | regulatory")


@router.post("/{agent_id}/kill")
def kill_agent(agent_id: int, data: KillRequest,
               auth: AuthContext = Depends(require_scope("govern")),
               db: Session = Depends(get_db)):
    """Terminate an agent immediately, irrevocably, and cryptographically.

    Regulatory basis: SR 26-2 §V.3 (Federal Reserve, effective 2026-04-17) and
    OCC Bulletin 2026-13 require every AI/ML system that takes autonomous
    action to have a documented kill-switch capability that terminates the
    system regardless of its cooperation.

    Guarantees:
      1. Status transitions to KILLED regardless of prior state.
      2. A hash-chained AuditRecord is written so the termination is
         cryptographically provable to an examiner.
      3. The kill fires a webhook (`agent.killed`) so downstream systems can
         de-register the agent.
      4. Attempting to kill an already-KILLED agent is idempotent — returns
         200 with `already_killed: true` rather than an error, so a repeated
         kill call under duress is safe.
    """
    from src.api.webhooks import dispatch_event
    from src.models.database import AuditRecord, compute_hash, get_last_hash
    import json
    import uuid

    agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if auth.org_id and agent.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="Agent not found")

    already_killed = agent.status == AgentStatus.KILLED
    prior_status = agent.status.value if agent.status else "unknown"

    now = datetime.utcnow()
    agent.status = AgentStatus.KILLED
    agent.governance_status = "killed"
    agent.updated_at = now

    # Hash-chain the termination onto the ledger so the kill is
    # cryptographically provable during an OCC / Fed / CFPB exam.
    decision_id = f"kill-{uuid.uuid4().hex[:12]}"
    previous_hash = get_last_hash(db)
    record_payload = {
        "decision_id": decision_id,
        "system_name": agent.name,
        "agent_id": agent.id,
        "action": "KILL_AGENT",
        "prior_status": prior_status,
        "kill_source": data.kill_source,
        "reason": data.reason,
        "already_killed": already_killed,
        "killed_by": auth.identity,
        "created_at": now.isoformat(),
    }
    current_hash = compute_hash({**record_payload, "previous_hash": previous_hash})
    audit = AuditRecord(
        decision_id=decision_id,
        system_name=agent.name,
        industry="agent_governance",
        audited_by=auth.identity,
        frameworks_audited="SR_26_2,OCC_2026_13,EU_AI_ACT",
        results=json.dumps(record_payload),
        risk_score=1.0,
        risk_level="CRITICAL",
        governance_action="KILL_AGENT",
        policy_version="kill-switch-v1",
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(audit)
    log_mutation(db, auth.identity, "kill", "agent", agent_id,
                 f"KILL from {prior_status} · source={data.kill_source} · reason={data.reason[:80]}")
    db.commit()

    try:
        dispatch_event("agent.killed", {
            "agent_id": agent.id,
            "name": agent.name,
            "prior_status": prior_status,
            "kill_source": data.kill_source,
            "reason": data.reason,
            "decision_id": decision_id,
            "already_killed": already_killed,
        }, agent.org_id, db)
    except Exception:  # noqa: BLE001 — never let webhook failure block the kill
        pass

    return {
        "agent_id": agent.id,
        "name": agent.name,
        "status": AgentStatus.KILLED.value,
        "prior_status": prior_status,
        "already_killed": already_killed,
        "kill_source": data.kill_source,
        "killed_by": auth.identity,
        "killed_at": now.isoformat(),
        "decision_id": decision_id,
        "current_hash": current_hash,
        "frameworks_cited": ["SR_26_2", "OCC_2026_13", "EU_AI_ACT"],
    }


@router.get("/{agent_id}/dependencies")
def get_agent_dependencies(agent_id: int, db: Session = Depends(get_db)):
    """Get the dependency graph for an agent."""
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
def scan_for_shadow_ai(data: ShadowScanRequest,
                       auth: AuthContext = Depends(require_scope("scan")),
                       db: Session = Depends(get_db)):
    """Scan for unauthorized/unregistered AI usage (Shadow AI detection)."""
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
                        org_id=auth.org_id,
                    )
                    db.add(det)
                    detections.append({"provider": info["provider"], "severity": info["severity"], "source": target, "registered": False})
                else:
                    detections.append({"provider": info["provider"], "severity": "info", "registered": True, "agent_id": existing.id})
    log_mutation(db, auth.identity, "create", "shadow_scan",
                 details=f"Scanned {len(data.targets)} targets, found {len([d for d in detections if not d.get('registered')])} unregistered")
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


class AutoScanRequest(BaseModel):
    window_hours: int = Field(default=24, ge=1, le=720,
                              description="Look-back window for usage + mutation signals.")
    limit: int = Field(default=5000, ge=100, le=50000,
                       description="Max rows to inspect per scanner.")
    persist: bool = Field(default=True,
                          description="If false, run in dry-run mode (no rows written).")


@router.post("/discovery/auto-scan")
def auto_scan_shadow_ai(data: AutoScanRequest,
                        auth: AuthContext = Depends(require_scope("scan")),
                        db: Session = Depends(get_db)):
    """Automatic shadow-AI detection from the platform's own signals.

    Unlike POST /discovery/scan which needs explicit targets, this endpoint
    sweeps three sources without any input:

      * UsageRecord — flags outbound calls to known LLM API domains
        (openai.com, anthropic.com, groq.com, azure.com/openai, bedrock,
        vertex, replicate, together, mistral, cohere, x.ai, huggingface).
      * MutationLog — flags bursts of identical mutations by a single actor
        (≥25 within 15 minutes) — smells like an unregistered agent.
      * ApiKey — flags active keys with principal_type='agent' pointing
        at agent_ids that no longer exist.

    Detections are written to ShadowAIDetection so they land on the
    existing /agents/discovery/detections list.
    """
    from src.shadow_ai import detector

    detections = detector.scan(
        db,
        window_hours=data.window_hours,
        limit=data.limit,
        persist=data.persist,
    )
    counts_by_severity = {}
    for d in detections:
        counts_by_severity[d["severity"]] = counts_by_severity.get(d["severity"], 0) + 1

    log_mutation(db, auth.identity, "create", "shadow_auto_scan",
                 details=f"window={data.window_hours}h found={len(detections)}")
    if not data.persist:
        db.commit()  # flush the mutation log even in dry-run

    risk_level = "critical" if counts_by_severity.get("high", 0) >= 3 else (
        "medium" if detections else "safe"
    )

    return {
        "window_hours": data.window_hours,
        "detections_found": len(detections),
        "counts_by_severity": counts_by_severity,
        "risk_level": risk_level,
        "persisted": data.persist,
        "detections": detections,
    }


@router.get("/discovery/detections")
def list_shadow_detections(status: Optional[str] = None,
                           pagination: PaginationParams = Depends(),
                           auth: AuthContext = Depends(verify_api_key_or_jwt),
                           db: Session = Depends(get_db)):
    """List all shadow AI detections."""
    query = db.query(ShadowAIDetection)
    if auth.org_id:
        query = query.filter(ShadowAIDetection.org_id == auth.org_id)
    if status:
        query = query.filter(ShadowAIDetection.status == status)
    total = query.count()
    dets = query.order_by(ShadowAIDetection.created_at.desc()).offset(pagination.offset).limit(pagination.per_page).all()
    return paginated_response(
        [
            {"id": d.id, "detection_type": d.detection_type, "description": d.description,
             "severity": d.severity, "status": d.status, "detected_service": d.detected_service,
             "created_at": d.created_at.isoformat() if d.created_at else None}
            for d in dets
        ],
        total, pagination.page, pagination.per_page,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Agent identity — first-class principals (P1-8)
# ═══════════════════════════════════════════════════════════════════════════

class AgentCredentialCreate(BaseModel):
    """Payload for issuing an agent-scoped API key."""
    name: str = Field(..., min_length=1, max_length=255,
                      description="Human label for this credential (e.g. 'prod-runtime', 'canary-eval')")
    scopes: str = Field(default="govern,risk,scan",
                        description="Comma-separated scope list this credential can exercise")
    rate_limit: int = Field(default=60, ge=1, le=10000,
                            description="Per-minute rate limit for this credential")
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=365,
                                           description="Auto-expiry; None disables")


def _load_agent_or_404(agent_id: int, db: Session, auth) -> "AIAgent":
    agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if auth.org_id and agent.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.post("/{agent_id}/credentials")
def issue_agent_credential(agent_id: int, data: AgentCredentialCreate,
                           auth: AuthContext = Depends(require_scope("govern")),
                           db: Session = Depends(get_db)):
    """Issue a fresh scoped API key bound to this specific agent.

    The returned `key` value is shown **once** — hash-only storage means we
    cannot show it again. Save it in your agent's secret store immediately.

    Enforces "no shared service accounts": every credential has an agent_id
    and a principal_type of "agent", so downstream audit logs can attribute
    every request to a specific agent identity.
    """
    from src.models.tenant import ApiKey, generate_api_key
    from datetime import timedelta

    agent = _load_agent_or_404(agent_id, db, auth)
    if agent.status == AgentStatus.KILLED:
        raise HTTPException(status_code=409,
                            detail="Cannot issue credentials for a KILLED agent")

    full_key, prefix, key_hash = generate_api_key()

    expires_at = None
    if data.expires_in_days is not None:
        expires_at = datetime.utcnow() + timedelta(days=data.expires_in_days)

    key_row = ApiKey(
        org_id=agent.org_id,
        agent_id=agent.id,
        principal_type="agent",
        name=data.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=data.scopes,
        rate_limit=data.rate_limit,
        expires_at=expires_at,
    )
    db.add(key_row)
    db.flush()
    log_mutation(db, auth.identity, "create", "agent_credential", str(key_row.id),
                 f"issued for agent={agent.id} name={data.name} scopes={data.scopes}")
    db.commit()

    return {
        "credential_id": key_row.id,
        "agent_id": agent.id,
        "name": key_row.name,
        "key": full_key,  # shown once
        "key_prefix": prefix,
        "principal_type": "agent",
        "scopes": key_row.scopes,
        "rate_limit": key_row.rate_limit,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "warning": "Store this key now — it will not be shown again.",
    }


class EvalCredentialCreate(BaseModel):
    """Preset for eval-only credentials — hard-capped by design.

    Every field a user could pass here that would broaden the credential's
    reach has been removed. The runtime hard-caps scopes to redteam,scan
    and TTL to 8 hours max regardless of what the caller requests.
    """
    name: str = Field(..., min_length=1, max_length=255,
                      description="Human label for this eval credential (e.g. 'harness-run-42')")
    ttl_hours: int = Field(default=4, ge=1, le=8,
                           description="TTL in hours; hard-capped at 8. Default 4.")


# Scopes that eval principals must NEVER hold. Enforced at issue time and
# at request-authorization time (see src/security/api_key_auth.py).
_EVAL_FORBIDDEN_SCOPES = {"govern", "audit"}
_EVAL_ALLOWED_SCOPES = "redteam,scan"


@router.post("/{agent_id}/credentials/eval")
def issue_eval_credential(agent_id: int, data: EvalCredentialCreate,
                          auth: AuthContext = Depends(require_scope("govern")),
                          db: Session = Depends(get_db)):
    """Issue an eval-only credential for this agent.

    Hard caps enforced regardless of caller input:
      * scopes = "redteam,scan" (no `govern`, no `audit`, ever)
      * TTL = min(requested, 8 hours)
      * principal_type = "eval" so downstream authorization checks can
        refuse to grant escalated scopes to an eval principal even if the
        `scopes` column is later tampered with.

    Rationale: eval runtimes are the industry's ungoverned blind spot
    (see the Aug 2026 OpenAI/HuggingFace/Meta/Anthropic incidents). An
    eval credential should be able to red-team the model and scan for
    findings — nothing else. Even if the eval harness is compromised,
    a stolen eval credential cannot exercise production governance.
    """
    from src.models.tenant import ApiKey, generate_api_key
    from datetime import timedelta

    agent = _load_agent_or_404(agent_id, db, auth)
    if agent.status in (AgentStatus.KILLED, AgentStatus.LOCKED_DOWN):
        raise HTTPException(status_code=409,
                            detail=f"Cannot issue credentials for a {agent.status.value} agent")

    ttl = min(max(1, data.ttl_hours), 8)
    full_key, prefix, key_hash = generate_api_key()
    expires_at = datetime.utcnow() + timedelta(hours=ttl)

    key_row = ApiKey(
        org_id=agent.org_id,
        agent_id=agent.id,
        principal_type="eval",
        name=data.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=_EVAL_ALLOWED_SCOPES,
        rate_limit=60,
        expires_at=expires_at,
    )
    db.add(key_row)
    db.flush()
    log_mutation(db, auth.identity, "create", "eval_credential", str(key_row.id),
                 f"eval-only for agent={agent.id} name={data.name} ttl_hours={ttl}")
    db.commit()

    return {
        "credential_id": key_row.id,
        "agent_id": agent.id,
        "name": key_row.name,
        "key": full_key,
        "key_prefix": prefix,
        "principal_type": "eval",
        "scopes": _EVAL_ALLOWED_SCOPES,
        "forbidden_scopes": sorted(_EVAL_FORBIDDEN_SCOPES),
        "ttl_hours": ttl,
        "expires_at": expires_at.isoformat(),
        "warning": "Store this key now — it will not be shown again.",
        "note": (
            "This credential cannot exercise `govern` or `audit` scopes even "
            "if its scope list is tampered with — enforcement is at request "
            "time via principal_type='eval'."
        ),
    }


@router.get("/{agent_id}/credentials")
def list_agent_credentials(agent_id: int,
                           auth: AuthContext = Depends(require_scope("govern")),
                           db: Session = Depends(get_db)):
    """List credentials for an agent (values redacted)."""
    from src.models.tenant import ApiKey
    _load_agent_or_404(agent_id, db, auth)
    creds = db.query(ApiKey).filter(ApiKey.agent_id == agent_id).all()
    return {
        "agent_id": agent_id,
        "count": len(creds),
        "credentials": [
            {
                "credential_id": c.id,
                "name": c.name,
                "key_prefix": c.key_prefix,
                "scopes": c.scopes,
                "is_active": c.is_active,
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
                "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in creds
        ],
    }


@router.post("/{agent_id}/credentials/{credential_id}/rotate")
def rotate_agent_credential(agent_id: int, credential_id: int,
                            auth: AuthContext = Depends(require_scope("govern")),
                            db: Session = Depends(get_db)):
    """Rotate an agent credential: mint a new value, invalidate the old."""
    from src.models.tenant import ApiKey, generate_api_key
    _load_agent_or_404(agent_id, db, auth)
    cred = (db.query(ApiKey)
              .filter(ApiKey.id == credential_id, ApiKey.agent_id == agent_id)
              .first())
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    full_key, prefix, key_hash = generate_api_key()
    cred.key_prefix = prefix
    cred.key_hash = key_hash
    cred.last_used_at = None
    log_mutation(db, auth.identity, "rotate", "agent_credential", str(cred.id),
                 f"rotated for agent={agent_id}")
    db.commit()
    return {
        "credential_id": cred.id,
        "agent_id": agent_id,
        "key": full_key,
        "key_prefix": prefix,
        "warning": "Store this key now — it will not be shown again.",
    }


@router.post("/{agent_id}/credentials/{credential_id}/revoke")
def revoke_agent_credential(agent_id: int, credential_id: int,
                            auth: AuthContext = Depends(require_scope("govern")),
                            db: Session = Depends(get_db)):
    """Immediately disable an agent credential."""
    from src.models.tenant import ApiKey
    _load_agent_or_404(agent_id, db, auth)
    cred = (db.query(ApiKey)
              .filter(ApiKey.id == credential_id, ApiKey.agent_id == agent_id)
              .first())
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    cred.is_active = False
    log_mutation(db, auth.identity, "revoke", "agent_credential", str(cred.id),
                 f"revoked for agent={agent_id}")
    db.commit()
    return {"credential_id": cred.id, "agent_id": agent_id, "is_active": False}


# ═══════════════════════════════════════════════════════════════════════════
# Agent budgets — enforced autonomy caps (P1-9)
# ═══════════════════════════════════════════════════════════════════════════

class AgentBudgetSet(BaseModel):
    step_budget: Optional[int] = Field(default=None, ge=0,
                                       description="Max steps/actions; None = uncapped")
    spend_budget_usd: Optional[float] = Field(default=None, ge=0,
                                              description="Max USD spend; None = uncapped")
    recursion_depth_limit: Optional[int] = Field(default=None, ge=0)
    period: str = Field(default="total", pattern=r"^(total|hourly|daily)$")
    on_exhaustion: str = Field(default="kill", pattern=r"^(kill|pause)$")


class AgentBudgetConsume(BaseModel):
    steps: int = Field(default=1, ge=0)
    spend_usd: float = Field(default=0.0, ge=0)
    recursion_depth: Optional[int] = Field(default=None, ge=0)


def _budget_dict(b, agent) -> dict:
    return {
        "agent_id": agent.id,
        "agent_status": agent.status.value if agent.status else None,
        "step_budget": b.step_budget,
        "spend_budget_usd": b.spend_budget_usd,
        "recursion_depth_limit": b.recursion_depth_limit,
        "used_steps": b.used_steps,
        "used_spend_usd": round(b.used_spend_usd, 4),
        "steps_remaining": (b.step_budget - b.used_steps) if b.step_budget is not None else None,
        "spend_remaining_usd": (
            round(b.spend_budget_usd - b.used_spend_usd, 4) if b.spend_budget_usd is not None else None
        ),
        "period": b.period,
        "period_start": b.period_start.isoformat() if b.period_start else None,
        "on_exhaustion": b.on_exhaustion,
    }


@router.post("/{agent_id}/budget")
def set_agent_budget(agent_id: int, data: AgentBudgetSet,
                     auth: AuthContext = Depends(require_scope("govern")),
                     db: Session = Depends(get_db)):
    """Set (or update) the enforced autonomy budget for an agent."""
    from src.models.agents import AgentBudget
    agent = _load_agent_or_404(agent_id, db, auth)
    budget = db.query(AgentBudget).filter(AgentBudget.agent_id == agent_id).first()
    if budget is None:
        budget = AgentBudget(agent_id=agent_id)
        db.add(budget)
    budget.step_budget = data.step_budget
    budget.spend_budget_usd = data.spend_budget_usd
    budget.recursion_depth_limit = data.recursion_depth_limit
    budget.period = data.period
    budget.on_exhaustion = data.on_exhaustion
    budget.period_start = datetime.utcnow()
    log_mutation(db, auth.identity, "update", "agent_budget", str(agent_id),
                 f"steps={data.step_budget} spend={data.spend_budget_usd} period={data.period}")
    db.commit()
    db.refresh(budget)
    return _budget_dict(budget, agent)


@router.get("/{agent_id}/budget")
def get_agent_budget(agent_id: int,
                     auth: AuthContext = Depends(require_scope("govern")),
                     db: Session = Depends(get_db)):
    """Return the current budget and consumption for an agent."""
    from src.models.agents import AgentBudget
    agent = _load_agent_or_404(agent_id, db, auth)
    budget = db.query(AgentBudget).filter(AgentBudget.agent_id == agent_id).first()
    if budget is None:
        raise HTTPException(status_code=404, detail="No budget set for this agent")
    return _budget_dict(budget, agent)


@router.post("/{agent_id}/budget/reset")
def reset_agent_budget(agent_id: int,
                       auth: AuthContext = Depends(require_scope("govern")),
                       db: Session = Depends(get_db)):
    """Zero out `used_steps` and `used_spend_usd`, restart the period window."""
    from src.models.agents import AgentBudget
    agent = _load_agent_or_404(agent_id, db, auth)
    budget = db.query(AgentBudget).filter(AgentBudget.agent_id == agent_id).first()
    if budget is None:
        raise HTTPException(status_code=404, detail="No budget set for this agent")
    budget.used_steps = 0
    budget.used_spend_usd = 0.0
    budget.period_start = datetime.utcnow()
    log_mutation(db, auth.identity, "reset", "agent_budget", str(agent_id))
    db.commit()
    db.refresh(budget)
    return _budget_dict(budget, agent)


@router.post("/{agent_id}/budget/consume")
def consume_agent_budget(agent_id: int, data: AgentBudgetConsume,
                         auth: AuthContext = Depends(require_scope("govern")),
                         db: Session = Depends(get_db)):
    """Charge steps/spend against the agent's budget.

    Called by the agent runtime after each action. If either cap is exceeded
    the endpoint returns `exhausted: true` and applies `on_exhaustion`:
      * `kill` — auto-transitions the agent to KILLED and hash-chains the
        termination onto the audit ledger (same behavior as an explicit kill).
      * `pause` — sets agent status to SUSPENDED without hash-chaining.

    Idempotent-ish: repeatedly calling after exhaustion is safe; the agent
    stays in its terminal state and subsequent responses report `exhausted`.
    """
    from src.models.agents import AgentBudget
    agent = _load_agent_or_404(agent_id, db, auth)
    budget = db.query(AgentBudget).filter(AgentBudget.agent_id == agent_id).first()
    if budget is None:
        raise HTTPException(status_code=404, detail="No budget set for this agent")

    budget.used_steps += data.steps
    budget.used_spend_usd += data.spend_usd

    step_exhausted = budget.step_budget is not None and budget.used_steps > budget.step_budget
    spend_exhausted = (
        budget.spend_budget_usd is not None and budget.used_spend_usd > budget.spend_budget_usd
    )
    recursion_exhausted = (
        budget.recursion_depth_limit is not None
        and data.recursion_depth is not None
        and data.recursion_depth > budget.recursion_depth_limit
    )
    exhausted = step_exhausted or spend_exhausted or recursion_exhausted

    action_taken = "none"
    kill_decision_id: Optional[str] = None

    if exhausted and agent.status != AgentStatus.KILLED and agent.status != AgentStatus.SUSPENDED:
        if budget.on_exhaustion == "kill":
            # Hash-chain the auto-kill just like a manual kill
            from src.api.webhooks import dispatch_event
            from src.models.database import AuditRecord, compute_hash, get_last_hash
            import json
            import uuid

            reasons = []
            if step_exhausted:  reasons.append(f"steps {budget.used_steps}/{budget.step_budget}")
            if spend_exhausted: reasons.append(f"spend ${budget.used_spend_usd:.2f}/${budget.spend_budget_usd:.2f}")
            if recursion_exhausted: reasons.append(f"recursion {data.recursion_depth}/{budget.recursion_depth_limit}")

            agent.status = AgentStatus.KILLED
            agent.governance_status = "killed"
            agent.updated_at = datetime.utcnow()

            decision_id = f"kill-budget-{uuid.uuid4().hex[:10]}"
            previous_hash = get_last_hash(db)
            payload = {
                "decision_id": decision_id,
                "system_name": agent.name,
                "agent_id": agent.id,
                "action": "KILL_AGENT",
                "kill_source": "auto_budget",
                "reason": "budget exhausted: " + ", ".join(reasons),
                "budget_snapshot": _budget_dict(budget, agent),
                "created_at": datetime.utcnow().isoformat(),
            }
            current_hash = compute_hash({**payload, "previous_hash": previous_hash})
            db.add(AuditRecord(
                decision_id=decision_id,
                system_name=agent.name,
                industry="agent_governance",
                audited_by=auth.identity,
                frameworks_audited="SR_26_2,OCC_2026_13",
                results=json.dumps(payload),
                risk_score=1.0,
                risk_level="CRITICAL",
                governance_action="KILL_AGENT",
                policy_version="budget-kill-v1",
                previous_hash=previous_hash,
                current_hash=current_hash,
            ))
            action_taken = "killed"
            kill_decision_id = decision_id
            try:
                dispatch_event("agent.killed", {
                    "agent_id": agent.id, "name": agent.name,
                    "kill_source": "auto_budget",
                    "reason": payload["reason"],
                    "decision_id": decision_id,
                }, agent.org_id, db)
            except Exception:  # noqa: BLE001
                pass
        else:  # pause
            agent.status = AgentStatus.SUSPENDED
            agent.governance_status = "suspended"
            agent.updated_at = datetime.utcnow()
            action_taken = "paused"

    db.commit()
    db.refresh(budget)
    db.refresh(agent)

    return {
        **_budget_dict(budget, agent),
        "exhausted": exhausted,
        "step_exhausted": step_exhausted,
        "spend_exhausted": spend_exhausted,
        "recursion_exhausted": recursion_exhausted,
        "action_taken": action_taken,
        "kill_decision_id": kill_decision_id,
    }
