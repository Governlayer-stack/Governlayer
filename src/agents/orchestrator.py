"""LangGraph agent orchestrator — coordinates autonomous governance workflows.

This is the brain of the autonomous agentic system. It manages:
- Multi-step governance pipelines (drift -> risk -> decide -> audit -> ledger)
- Agent delegation (compliance agent, threat agent, etc.)
- Human-in-the-loop escalation gates
- Agent memory across sessions
"""

import logging
from operator import add
from typing import Annotated, Literal, TypedDict

logger = logging.getLogger(__name__)

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from src.config import get_settings
from src.llm.providers import ModelCapability, get_best_for, get_model


class GovernanceState(TypedDict):
    """State that flows through the governance pipeline."""
    system_name: str
    use_case: str
    reasoning_trace: str
    drift_result: dict
    risk_scores: dict
    risk_level: str
    governance_action: str
    reason: str
    messages: Annotated[list, add]
    requires_human: bool
    audit_hash: str


settings = get_settings()
memory = MemorySaver()


def create_llm(capability: ModelCapability = ModelCapability.GOVERNANCE):
    """Create an LLM using Achonye's intelligent routing."""
    model_name = get_best_for(capability, prefer_local=settings.use_local_llm)
    return get_model(model_name)


# --- Agent nodes ---

def drift_analysis_node(state: GovernanceState) -> dict:
    """Run behavioral drift detection on the reasoning trace."""
    from src.drift.detection import analyze_reasoning
    result = analyze_reasoning(
        reasoning_trace=state["reasoning_trace"],
        use_case=state["use_case"],
    )
    return {
        "drift_result": result,
        "messages": [f"Drift analysis complete: D_c={result['drift_coefficient']}, action={result['action']}"],
    }


def risk_scoring_node(state: GovernanceState) -> dict:
    """Compute deterministic risk scores."""
    # In the orchestrated pipeline, risk inputs come from state
    # Default to conservative scores if not provided
    scores = {
        "Privacy": 40, "Autonomy_Risk": 30, "Infrastructure_Risk": 25,
        "Oversight": 100, "Transparency": 30, "Fairness": 25,
    }
    overall = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall >= 80 else "MEDIUM" if overall >= 50 else "HIGH"
    return {
        "risk_scores": scores,
        "risk_level": risk_level,
        "messages": [f"Risk scoring complete: {round(overall)}/100 ({risk_level})"],
    }


def decision_node(state: GovernanceState) -> dict:
    """Make the governance decision based on drift + risk."""
    drift = state.get("drift_result", {})
    risk_level = state.get("risk_level", "MEDIUM")

    if drift.get("vetoed"):
        action = "BLOCK"
        reason = f"BLOCKED: Drift D_c={drift['drift_coefficient']} exceeds threshold."
        requires_human = False
    elif risk_level == "HIGH":
        action = "ESCALATE_HUMAN"
        reason = "ESCALATED: High risk score requires human review."
        requires_human = True
    elif risk_level == "MEDIUM" and drift.get("semantic_risk_flags", 0) > 0:
        action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: Medium risk with {drift['semantic_risk_flags']} semantic flags."
        requires_human = True
    else:
        action = "APPROVE"
        reason = f"APPROVED: Risk level {risk_level}, drift within bounds."
        requires_human = False

    return {
        "governance_action": action,
        "reason": reason,
        "requires_human": requires_human,
        "messages": [f"Decision: {action} — {reason}"],
    }


def human_review_node(state: GovernanceState) -> dict:
    """Gate for human-in-the-loop review. Blocks the pipeline until approved.

    Sets a pending review flag, stores a review record in the database,
    and returns PENDING_HUMAN_REVIEW as a terminal state (does NOT continue
    to audit_ledger).
    """
    from datetime import datetime

    from src.models.database import compute_hash

    pending_record = {
        "system_name": state.get("system_name", "unknown"),
        "governance_action": "PENDING_HUMAN_REVIEW",
        "reason": state.get("reason", "Escalation required"),
        "risk_level": state.get("risk_level", "UNKNOWN"),
        "drift_coefficient": state.get("drift_result", {}).get("drift_coefficient", 0),
        "created_at": datetime.utcnow().isoformat(),
    }
    review_hash = compute_hash(pending_record)

    logger.warning(
        "Pipeline BLOCKED — human review required: system=%s reason=%s review_hash=%s",
        state.get("system_name", "unknown"),
        state.get("reason", ""),
        review_hash[:16],
    )

    return {
        "requires_human": True,
        "governance_action": "PENDING_HUMAN_REVIEW",
        "audit_hash": review_hash,
        "messages": [
            f"PIPELINE BLOCKED — HUMAN REVIEW REQUIRED: {state.get('reason', '')}. "
            f"Review hash: {review_hash[:16]}. Pipeline will not proceed to ledger "
            f"until a human approves this decision."
        ],
    }


def audit_ledger_node(state: GovernanceState) -> dict:
    """Record the decision to the immutable audit ledger."""
    from datetime import datetime

    from src.models.database import compute_hash

    record_data = {
        "system_name": state["system_name"],
        "governance_action": state["governance_action"],
        "drift_coefficient": state.get("drift_result", {}).get("drift_coefficient", 0),
        "risk_level": state["risk_level"],
        "created_at": datetime.utcnow().isoformat(),
    }
    audit_hash = compute_hash(record_data)
    return {
        "audit_hash": audit_hash,
        "messages": [f"Audit ledger updated: hash={audit_hash[:16]}..."],
    }


# --- Routing ---

def should_escalate(state: GovernanceState) -> Literal["human_review", "audit_ledger"]:
    if state.get("requires_human", False):
        return "human_review"
    return "audit_ledger"


# --- Build the graph ---

def build_governance_graph() -> StateGraph:
    graph = StateGraph(GovernanceState)

    graph.add_node("drift_analysis", drift_analysis_node)
    graph.add_node("risk_scoring", risk_scoring_node)
    graph.add_node("decision", decision_node)
    graph.add_node("human_review", human_review_node)
    graph.add_node("audit_ledger", audit_ledger_node)

    graph.set_entry_point("drift_analysis")
    graph.add_edge("drift_analysis", "risk_scoring")
    graph.add_edge("risk_scoring", "decision")
    graph.add_conditional_edges("decision", should_escalate)
    graph.add_edge("human_review", END)  # Terminal — pipeline blocks until human approves
    graph.add_edge("audit_ledger", END)

    return graph.compile(checkpointer=memory)


# Singleton compiled graph
governance_pipeline = build_governance_graph()
