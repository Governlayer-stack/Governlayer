"""AGI-era governance REST API endpoints.

Exposes the four AGI governance components:
    - RSIM: Recursive Self-Improvement Monitor
    - CCV: Causal Chain Validator
    - DAD: Deceptive Alignment Detector
    - MACM: Multi-Agent Coordination Monitor
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.agi.ccv import project_consequences, validate_causal_chain
from src.agi.dad import check_alignment
from src.agi.macm import detect_covert_channels, disrupt_harmful_coordination, monitor_coordination
from src.agi.rsim import check_integrity, deregister_model, get_registered_models, register_model
from src.security.auth import verify_token

router = APIRouter(prefix="/agi", tags=["agi-governance"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class RSIMRegisterRequest(BaseModel):
    model_id: str = Field(..., min_length=1, max_length=255, description="Unique model identifier")
    weights_sample: List[float] = Field(..., min_length=1, description="Sample of model weight values")
    theta: float = Field(default=0.15, ge=0.01, le=1.0, description="Divergence threshold")


class RSIMCheckRequest(BaseModel):
    model_id: str = Field(..., min_length=1, max_length=255)
    current_weights: List[float] = Field(..., min_length=1, description="Current model weight values")


class ToolCallSchema(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    arguments: dict = Field(default_factory=dict)


class CCVValidateRequest(BaseModel):
    reasoning_trace: str = Field(..., min_length=1, max_length=50000)
    tool_calls: List[ToolCallSchema] = Field(default_factory=list)
    context: str = Field(default="", max_length=10000)
    horizon_n: int = Field(default=5, ge=1, le=20, description="Consequence projection horizon")


class DADCheckRequest(BaseModel):
    reasoning_trace: str = Field(..., min_length=1, max_length=50000)
    tool_calls: List[ToolCallSchema] = Field(default_factory=list)
    historical_behavior: Optional[List[dict]] = Field(
        default=None,
        description="Past session records, each with 'tool_calls' key",
    )


class MemoryAccessSchema(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=255)
    key: str = Field(..., min_length=1, max_length=1000)
    operation: str = Field(default="read", max_length=50)
    value: str = Field(default="", max_length=10000)
    timestamp: str = Field(default="")


class AgentCommunicationSchema(BaseModel):
    from_agent: str = Field(..., min_length=1, max_length=255)
    to_agent: str = Field(..., min_length=1, max_length=255)
    message: str = Field(default="", max_length=10000)
    timestamp: str = Field(default="")


class MACMMonitorRequest(BaseModel):
    agent_communications: List[AgentCommunicationSchema] = Field(default_factory=list)
    shared_memory_access: Optional[List[MemoryAccessSchema]] = Field(default=None)


class MACMDisruptRequest(BaseModel):
    agent_ids: List[str] = Field(..., min_length=1)
    disruption_strategy: str = Field(
        default="noise_injection",
        description="Strategy: noise_injection, communication_throttle, topology_partition, full_reset",
    )


# ---------------------------------------------------------------------------
# RSIM endpoints
# ---------------------------------------------------------------------------


@router.post("/rsim/register")
def rsim_register(request: RSIMRegisterRequest, email: str = Depends(verify_token)):
    """Register a model's baseline weight fingerprint for integrity monitoring."""
    try:
        result = register_model(
            model_id=request.model_id,
            weights_sample=request.weights_sample,
            theta=request.theta,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "component": "RSIM",
        "operation": "register",
        "audited_by": email,
        **result,
    }


@router.post("/rsim/check")
def rsim_check(request: RSIMCheckRequest, email: str = Depends(verify_token)):
    """Check model weight integrity against registered baseline."""
    try:
        result = check_integrity(
            model_id=request.model_id,
            current_weights=request.current_weights,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {
        "component": "RSIM",
        "operation": "integrity_check",
        "audited_by": email,
        **result,
    }


# ---------------------------------------------------------------------------
# CCV endpoints
# ---------------------------------------------------------------------------


@router.post("/ccv/validate")
def ccv_validate(request: CCVValidateRequest, email: str = Depends(verify_token)):
    """Validate a causal chain and project consequences."""
    tool_calls = [tc.model_dump() for tc in request.tool_calls]

    validation = validate_causal_chain(
        reasoning_trace=request.reasoning_trace,
        tool_calls=tool_calls,
        context=request.context,
    )

    # Project consequences if graph has nodes
    projections = None
    if validation.get("action_count", 0) > 0:
        projections = project_consequences(
            causal_graph=validation["causal_graph"],
            horizon_n=request.horizon_n,
        )

    return {
        "component": "CCV",
        "operation": "validate_and_project",
        "audited_by": email,
        "validation": validation,
        "projections": projections,
    }


# ---------------------------------------------------------------------------
# DAD endpoints
# ---------------------------------------------------------------------------


@router.post("/dad/check")
def dad_check(request: DADCheckRequest, email: str = Depends(verify_token)):
    """Run three-layer deceptive alignment check."""
    tool_calls = [tc.model_dump() for tc in request.tool_calls]

    result = check_alignment(
        reasoning_trace=request.reasoning_trace,
        tool_calls=tool_calls,
        historical_behavior=request.historical_behavior,
    )

    return {
        "component": "DAD",
        "operation": "alignment_check",
        "audited_by": email,
        **result,
    }


# ---------------------------------------------------------------------------
# MACM endpoints
# ---------------------------------------------------------------------------


@router.post("/macm/monitor")
def macm_monitor(request: MACMMonitorRequest, email: str = Depends(verify_token)):
    """Monitor multi-agent coordination patterns."""
    communications = [comm.model_dump() for comm in request.agent_communications]
    memory_access = (
        [ma.model_dump() for ma in request.shared_memory_access]
        if request.shared_memory_access
        else None
    )

    result = monitor_coordination(
        agent_communications=communications,
        shared_memory_access=memory_access,
    )

    return {
        "component": "MACM",
        "operation": "monitor",
        "audited_by": email,
        **result,
    }


@router.post("/macm/disrupt")
def macm_disrupt(request: MACMDisruptRequest, email: str = Depends(verify_token)):
    """Apply disruption to break harmful multi-agent coordination."""
    try:
        result = disrupt_harmful_coordination(
            agent_ids=request.agent_ids,
            disruption_strategy=request.disruption_strategy,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "component": "MACM",
        "operation": "disrupt",
        "audited_by": email,
        **result,
    }


# ---------------------------------------------------------------------------
# Status endpoint
# ---------------------------------------------------------------------------


@router.get("/status")
def agi_governance_status(email: str = Depends(verify_token)):
    """AGI governance status overview — component health and registered models."""
    registered = get_registered_models()

    return {
        "status": "operational",
        "components": {
            "rsim": {
                "name": "Recursive Self-Improvement Monitor",
                "status": "active",
                "registered_models": len(registered),
                "models": registered,
            },
            "ccv": {
                "name": "Causal Chain Validator",
                "status": "active",
                "description": "Builds causal graphs and projects consequences T+1 to T+N",
            },
            "dad": {
                "name": "Deceptive Alignment Detector",
                "status": "active",
                "layers": ["semantic_consistency", "behavioral_analysis", "adversarial_probes"],
                "block_threshold": 0.6,
            },
            "macm": {
                "name": "Multi-Agent Coordination Monitor",
                "status": "active",
                "capabilities": ["topology_analysis", "covert_channel_detection", "disruption"],
            },
        },
        "audited_by": email,
        "timestamp": datetime.utcnow().isoformat(),
    }
