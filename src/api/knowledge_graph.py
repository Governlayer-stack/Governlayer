"""Knowledge Graph & Advisory API — regulation mapping, gap analysis, recommendations."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.governance.knowledge_graph import (
    query_knowledge_graph,
    get_compliance_gap_analysis,
    get_advisory_recommendations,
    KNOWLEDGE_GRAPH,
)

router = APIRouter(prefix="/v1/knowledge", tags=["Knowledge Graph"])


class GapAnalysisRequest(BaseModel):
    active_controls: List[str] = Field(default_factory=list)


class AdvisoryRequest(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)


@router.get("/graph")
def get_graph(regulation: Optional[str] = None, control: Optional[str] = None,
              risk_category: Optional[str] = None):
    """Query the governance knowledge graph.

    Shows relationships between regulations, controls, and risk categories.
    Pass one parameter to explore connections, or none to see the full graph overview.
    """
    return query_knowledge_graph(
        regulation=regulation,
        control=control,
        risk_category=risk_category,
    )


@router.get("/regulations")
def list_all_regulations():
    """List all supported regulations with details."""
    return {
        "total": len(KNOWLEDGE_GRAPH["regulations"]),
        "regulations": [
            {"id": rid, **rdata}
            for rid, rdata in KNOWLEDGE_GRAPH["regulations"].items()
        ],
    }


@router.get("/controls")
def list_all_controls():
    """List all governance controls and their GovernLayer API mappings."""
    return {
        "total": len(KNOWLEDGE_GRAPH["controls"]),
        "controls": [
            {"id": cid, **cdata}
            for cid, cdata in KNOWLEDGE_GRAPH["controls"].items()
        ],
    }


@router.get("/risks")
def list_risk_categories():
    """List all risk categories with severity and related controls."""
    return {
        "total": len(KNOWLEDGE_GRAPH["risk_categories"]),
        "risk_categories": [
            {"id": rid, **rdata}
            for rid, rdata in KNOWLEDGE_GRAPH["risk_categories"].items()
        ],
    }


@router.post("/gap-analysis")
def compliance_gap_analysis(data: GapAnalysisRequest):
    """Analyze compliance gaps across all regulations based on active controls.

    Pass the list of controls you have active (e.g., ["risk_assessment", "bias_testing"])
    to see which regulations have gaps and what's missing.
    """
    return get_compliance_gap_analysis(data.active_controls)


@router.post("/advisory")
def get_recommendations(data: AdvisoryRequest):
    """Get prioritized governance advisory recommendations.

    Pass context about your environment (risk_score, fairness_tested, has_model_card, etc.)
    to receive tailored recommendations with specific actions and regulatory citations.
    """
    return get_advisory_recommendations(data.context)
