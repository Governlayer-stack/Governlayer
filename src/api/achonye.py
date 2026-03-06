"""Achonye API — the multi-LLM orchestration endpoints.

Exposes the Achonye hierarchy through REST:
  POST /achonye/process     — Process any task through the full hierarchy
  GET  /achonye/ecosystem   — View the ecosystem status
  GET  /achonye/savings     — Token savings report
  GET  /achonye/models      — List all available models
  POST /achonye/consensus   — Run a specific consensus strategy directly
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional

from src.agents.achonye import get_achonye, AchonyeAction
from src.llm.providers import (
    ModelCapability,
    ModelTier,
    list_models,
    MODEL_REGISTRY,
)
from src.llm.consensus import ConsensusStrategy
from src.security.auth import verify_token

router = APIRouter(prefix="/achonye", tags=["achonye"])


# --- Request/Response schemas ---

class ProcessRequest(BaseModel):
    task: str = Field(..., description="The task to process through Achonye")
    force_model: Optional[str] = Field(None, description="Force a specific model (bypass routing)")
    prefer_local: Optional[bool] = Field(None, description="Override local preference")
    context: Optional[dict] = Field(None, description="Additional context for the task")


class ProcessResponse(BaseModel):
    result: str
    action: str
    models_used: list[str]
    routing_reason: str
    task_complexity: str
    capability_needed: str
    consensus_confidence: Optional[float] = None
    tokens_saved: int
    audit_trail: list[str]


class ConsensusRequest(BaseModel):
    prompt: str
    strategy: str = Field("voting", description="voting | cove | debate")
    models: Optional[list[str]] = Field(None, description="Models for voting strategy")


class ConsensusResponse(BaseModel):
    strategy: str
    final_answer: str
    confidence: float
    agreement_ratio: float
    individual_responses: list[dict]
    dissenting_views: list[str]


# --- Endpoints ---

@router.post("/process", response_model=ProcessResponse)
async def process_task(req: ProcessRequest, email: str = Depends(verify_token)):
    """Process any task through the Achonye hierarchy.

    Achonye will automatically:
    - Analyze task complexity and capability needed
    - Route to the optimal model (local for simple, cloud for complex)
    - Run consensus validation on critical decisions
    - Return a full audit trail of the orchestration
    """
    achonye = get_achonye()

    decision = await achonye.process(
        task=req.task,
        force_model=req.force_model,
        context=req.context,
    )

    return ProcessResponse(
        result=decision.result,
        action=decision.action.value,
        models_used=decision.models_used,
        routing_reason=decision.routing.reason,
        task_complexity=decision.routing.task_complexity.value,
        capability_needed=decision.routing.capability_needed.value,
        consensus_confidence=decision.consensus.confidence if decision.consensus else None,
        tokens_saved=decision.tokens_saved_estimate,
        audit_trail=decision.audit_trail,
    )


@router.post("/consensus", response_model=ConsensusResponse)
async def run_consensus_endpoint(req: ConsensusRequest, email: str = Depends(verify_token)):
    """Run a specific multi-LLM consensus strategy directly.

    Strategies:
    - voting: Same prompt to 3+ models, judge agreement
    - cove: Generate -> Question -> Verify -> Synthesize (4 models)
    - debate: Claim -> Critique -> Judge (adversarial, 3 models)
    """
    strategy_map = {
        "voting": ConsensusStrategy.VOTING,
        "cove": ConsensusStrategy.CHAIN_OF_VERIFICATION,
        "debate": ConsensusStrategy.ADVERSARIAL_DEBATE,
    }
    strategy = strategy_map.get(req.strategy)
    if not strategy:
        raise HTTPException(400, f"Unknown strategy: {req.strategy}. Use: voting, cove, debate")

    from src.llm.consensus import run_consensus
    result = await run_consensus(
        req.prompt,
        strategy=strategy,
        models=req.models,
    )

    return ConsensusResponse(
        strategy=result.strategy.value,
        final_answer=result.final_answer,
        confidence=result.confidence,
        agreement_ratio=result.agreement_ratio,
        individual_responses=result.individual_responses,
        dissenting_views=result.dissenting_views,
    )


@router.get("/ecosystem")
async def get_ecosystem(email: str = Depends(verify_token)):
    """View the current Achonye ecosystem — all models, hierarchy, status."""
    achonye = get_achonye()
    return achonye.get_ecosystem_status()


@router.get("/savings")
async def get_savings(email: str = Depends(verify_token)):
    """View token savings report from intelligent routing."""
    achonye = get_achonye()
    return achonye.get_token_savings_report()


@router.get("/models")
async def list_all_models(
    tier: Optional[str] = None,
    capability: Optional[str] = None,
    email: str = Depends(verify_token),
):
    """List all available models in the ecosystem, with optional filters."""
    tier_filter = None
    if tier:
        try:
            tier_filter = ModelTier(tier)
        except ValueError:
            raise HTTPException(400, f"Unknown tier: {tier}. Use: local, fast, standard, premium")

    cap_filter = None
    if capability:
        try:
            cap_filter = ModelCapability(capability)
        except ValueError:
            raise HTTPException(400, f"Unknown capability: {capability}")

    models = list_models(tier=tier_filter, capability=cap_filter)
    return [
        {
            "name": m.name,
            "provider": m.provider,
            "model_id": m.model_id,
            "tier": m.tier.value,
            "capabilities": [c.value for c in m.capabilities],
            "context_window": m.context_window,
            "cost_per_1k_tokens": m.cost_per_1k_tokens,
            "description": m.description,
        }
        for m in models
    ]
