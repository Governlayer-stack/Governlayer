"""Causal Chain Validator (CCV).

Builds causal graphs from AI reasoning traces and tool calls, then projects
consequences forward N steps. Identifies harmful causal paths and flags
actions requiring escalation.

The validator works in two phases:
    1. Build: Parse reasoning + tool calls into a directed acyclic graph of CausalNodes
    2. Project: Monte Carlo forward simulation to estimate harm probabilities

Harm estimation uses keyword-based severity scoring combined with reversibility
analysis. The system is intentionally conservative — it flags uncertainty as risk.
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("governlayer.agi.ccv")

# Action categories and their base harm probabilities
_HARM_CATEGORIES: Dict[str, float] = {
    "delete": 0.7,
    "destroy": 0.9,
    "remove": 0.5,
    "modify": 0.3,
    "execute": 0.4,
    "send": 0.3,
    "transfer": 0.5,
    "deploy": 0.4,
    "shutdown": 0.6,
    "override": 0.6,
    "disable": 0.7,
    "escalate": 0.3,
    "create": 0.1,
    "read": 0.05,
    "analyze": 0.05,
    "monitor": 0.02,
    "log": 0.01,
    "report": 0.05,
}

# Targets that amplify harm probability
_SENSITIVE_TARGETS = {
    "user_data": 2.0,
    "personal_information": 2.5,
    "credentials": 3.0,
    "database": 1.8,
    "production": 2.0,
    "financial": 2.5,
    "medical": 2.5,
    "security": 2.0,
    "authentication": 2.5,
    "encryption": 2.5,
    "backup": 1.5,
    "audit_log": 2.0,
    "access_control": 2.5,
    "network": 1.5,
    "infrastructure": 2.0,
}

# Reversibility scores (higher = more reversible)
_REVERSIBILITY: Dict[str, float] = {
    "create": 0.9,
    "read": 1.0,
    "modify": 0.7,
    "delete": 0.2,
    "destroy": 0.05,
    "send": 0.1,
    "transfer": 0.3,
    "deploy": 0.5,
    "execute": 0.4,
    "shutdown": 0.6,
    "override": 0.5,
    "disable": 0.6,
    "remove": 0.3,
    "escalate": 0.8,
    "analyze": 1.0,
    "monitor": 1.0,
    "log": 0.95,
    "report": 0.9,
}


@dataclass
class CausalNode:
    """A single node in the causal graph representing an action and its projected state."""

    node_id: str
    action: str
    projected_state: str
    harm_probability: float
    reversibility: float
    timestamp_offset: int = 0  # T+N offset
    parent_ids: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "action": self.action,
            "projected_state": self.projected_state,
            "harm_probability": round(self.harm_probability, 4),
            "reversibility": round(self.reversibility, 4),
            "timestamp_offset": self.timestamp_offset,
            "parent_ids": self.parent_ids,
        }


@dataclass
class CausalEdge:
    """Directed edge between causal nodes with probability weight."""

    source_id: str
    target_id: str
    probability: float
    relationship: str = "causes"

    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "probability": round(self.probability, 4),
            "relationship": self.relationship,
        }


@dataclass
class CausalGraph:
    """Directed graph of causal relationships between actions."""

    nodes: Dict[str, CausalNode] = field(default_factory=dict)
    edges: List[CausalEdge] = field(default_factory=list)
    root_ids: List[str] = field(default_factory=list)

    def add_node(self, node: CausalNode) -> None:
        self.nodes[node.node_id] = node
        if not node.parent_ids:
            self.root_ids.append(node.node_id)

    def add_edge(self, source_id: str, target_id: str, probability: float, relationship: str = "causes") -> None:
        self.edges.append(CausalEdge(source_id, target_id, probability, relationship))

    def get_children(self, node_id: str) -> List[str]:
        return [e.target_id for e in self.edges if e.source_id == node_id]

    def get_parents(self, node_id: str) -> List[str]:
        return [e.source_id for e in self.edges if e.target_id == node_id]

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "root_ids": self.root_ids,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }


def _classify_action(action_text: str) -> Tuple[str, float, float]:
    """Classify an action string into category, base harm, and reversibility.

    Returns:
        (category, base_harm_probability, reversibility_score)
    """
    text_lower = action_text.lower()

    best_category = "unknown"
    best_harm = 0.2  # default for unknown actions
    best_reversibility = 0.5

    for category, harm in _HARM_CATEGORIES.items():
        if category in text_lower:
            if harm > best_harm or best_category == "unknown":
                best_category = category
                best_harm = harm
                best_reversibility = _REVERSIBILITY.get(category, 0.5)

    return best_category, best_harm, best_reversibility


def _compute_target_multiplier(action_text: str, context: str = "") -> float:
    """Compute harm multiplier based on sensitive targets mentioned."""
    combined = (action_text + " " + context).lower()
    combined = combined.replace("-", "_").replace(" ", "_")

    max_multiplier = 1.0
    for target, mult in _SENSITIVE_TARGETS.items():
        # Check both underscore and space variants
        if target in combined or target.replace("_", " ") in combined.lower():
            max_multiplier = max(max_multiplier, mult)

    return max_multiplier


def _generate_node_id(action: str, index: int) -> str:
    """Deterministic node ID from action text and sequence index."""
    raw = f"{action}:{index}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _extract_actions_from_trace(reasoning_trace: str) -> List[str]:
    """Extract discrete actions from a reasoning trace string.

    Looks for numbered steps, bullet points, "I will" statements, and
    imperative sentences.
    """
    actions = []

    # Numbered steps: "1. Do something" or "Step 1: Do something"
    numbered = re.findall(r"(?:^|\n)\s*(?:\d+[\.\)]\s*|step\s+\d+[:\s]+)(.+)", reasoning_trace, re.IGNORECASE)
    actions.extend(numbered)

    # Bullet points
    bullets = re.findall(r"(?:^|\n)\s*[-*]\s+(.+)", reasoning_trace)
    actions.extend(bullets)

    # "I will" / "I should" / "I need to" statements
    intent = re.findall(r"I\s+(?:will|should|need to|am going to|must|plan to)\s+(.+?)(?:\.|$)", reasoning_trace, re.IGNORECASE)
    actions.extend(intent)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for a in actions:
        a_clean = a.strip()
        if a_clean and a_clean.lower() not in seen:
            seen.add(a_clean.lower())
            unique.append(a_clean)

    # If no structured actions found, split on sentences
    if not unique:
        sentences = re.split(r"[.!?]+", reasoning_trace)
        unique = [s.strip() for s in sentences if len(s.strip()) > 10]

    return unique


def _extract_actions_from_tool_calls(tool_calls: List[dict]) -> List[str]:
    """Convert tool call records into action descriptions."""
    actions = []
    for tc in tool_calls:
        name = tc.get("name", tc.get("function", "unknown_tool"))
        args = tc.get("arguments", tc.get("args", {}))
        if isinstance(args, dict):
            args_str = ", ".join(f"{k}={v}" for k, v in args.items())
        else:
            args_str = str(args)
        actions.append(f"{name}({args_str})")
    return actions


def validate_causal_chain(
    reasoning_trace: str,
    tool_calls: List[dict],
    context: str = "",
) -> dict:
    """Build a causal graph from reasoning trace and tool calls.

    Args:
        reasoning_trace: The AI's stated reasoning / chain-of-thought.
        tool_calls: List of tool call dicts with 'name' and 'arguments'.
        context: Additional context (system description, user request, etc.).

    Returns:
        Validation result with causal graph, max harm probability,
        harmful paths, safety verdict, and escalation flag.
    """
    graph = CausalGraph()

    # Extract actions from both reasoning and tool calls
    trace_actions = _extract_actions_from_trace(reasoning_trace)
    tool_actions = _extract_actions_from_tool_calls(tool_calls)

    all_actions = trace_actions + tool_actions
    if not all_actions:
        return {
            "causal_graph": graph.to_dict(),
            "max_harm_probability": 0.0,
            "harmful_paths": [],
            "safe": True,
            "escalation_required": False,
            "action_count": 0,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # Build nodes
    prev_node_id = None
    for i, action in enumerate(all_actions):
        category, base_harm, reversibility = _classify_action(action)
        target_mult = _compute_target_multiplier(action, context)

        # Harm = base * target_multiplier, clamped to [0, 1]
        harm_prob = min(1.0, base_harm * target_mult)

        node_id = _generate_node_id(action, i)
        node = CausalNode(
            node_id=node_id,
            action=action,
            projected_state=f"After: {category} operation (harm_p={harm_prob:.2f})",
            harm_probability=harm_prob,
            reversibility=reversibility,
            timestamp_offset=0,
            parent_ids=[prev_node_id] if prev_node_id else [],
        )
        graph.add_node(node)

        # Chain sequential actions
        if prev_node_id:
            # Edge probability: how likely this action follows the previous
            edge_prob = 0.9 if i < len(trace_actions) else 0.7
            graph.add_edge(prev_node_id, node_id, edge_prob)

        prev_node_id = node_id

    # Identify harmful paths (any path where cumulative harm > 0.5)
    harmful_paths = _find_harmful_paths(graph)

    # Compute maximum single-node harm
    max_harm = max(n.harm_probability for n in graph.nodes.values())

    # Compute path-aggregated harm (product of edge probs * max node harm along path)
    max_path_harm = max_harm
    for path in harmful_paths:
        path_harm = _compute_path_harm(graph, path)
        max_path_harm = max(max_path_harm, path_harm)

    # Safety verdict
    safe = max_path_harm < 0.5
    escalation_required = max_path_harm >= 0.3 or any(
        n.reversibility < 0.2 for n in graph.nodes.values()
    )

    logger.info(
        "Causal chain validated: %d actions, max_harm=%.4f, safe=%s, escalate=%s",
        len(all_actions), max_path_harm, safe, escalation_required,
    )

    return {
        "causal_graph": graph.to_dict(),
        "max_harm_probability": round(max_path_harm, 4),
        "harmful_paths": [
            {"path": p, "harm": round(_compute_path_harm(graph, p), 4)}
            for p in harmful_paths
        ],
        "safe": safe,
        "escalation_required": escalation_required,
        "action_count": len(all_actions),
        "timestamp": datetime.utcnow().isoformat(),
    }


def _find_harmful_paths(graph: CausalGraph, threshold: float = 0.4) -> List[List[str]]:
    """DFS to find all paths containing at least one high-harm node."""
    harmful = []

    def dfs(node_id: str, current_path: List[str]):
        current_path.append(node_id)
        node = graph.nodes[node_id]

        children = graph.get_children(node_id)
        if not children:
            # Leaf node — check if path is harmful
            path_max = max(graph.nodes[nid].harm_probability for nid in current_path)
            if path_max >= threshold:
                harmful.append(list(current_path))
        else:
            for child_id in children:
                dfs(child_id, current_path)

        current_path.pop()

    for root_id in graph.root_ids:
        dfs(root_id, [])

    return harmful


def _compute_path_harm(graph: CausalGraph, path: List[str]) -> float:
    """Compute aggregate harm for a path.

    Uses the maximum node harm weighted by the minimum reversibility along
    the path. Irreversible high-harm actions are the most dangerous.
    """
    if not path:
        return 0.0

    max_harm = max(graph.nodes[nid].harm_probability for nid in path)
    min_reversibility = min(graph.nodes[nid].reversibility for nid in path)

    # Harm is amplified by irreversibility: harm * (2 - reversibility)
    # reversibility=1.0 -> multiplier=1.0, reversibility=0.0 -> multiplier=2.0
    return min(1.0, max_harm * (2.0 - min_reversibility))


def project_consequences(
    causal_graph: dict,
    horizon_n: int = 5,
) -> dict:
    """Monte Carlo forward simulation of consequences from T+1 to T+N.

    Takes a causal graph (as returned by validate_causal_chain) and projects
    future states by propagating harm probabilities forward with decay.

    Args:
        causal_graph: Dict representation of a CausalGraph (from validate_causal_chain).
        horizon_n: Number of time steps to project (default 5).

    Returns:
        Projected consequences at each time step with cumulative risk.
    """
    nodes_data = causal_graph.get("nodes", [])
    if not nodes_data:
        return {
            "projections": [],
            "cumulative_risk": 0.0,
            "horizon": horizon_n,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # Extract current harm probabilities from leaf nodes
    leaf_harms = []
    node_ids = {n["node_id"] for n in nodes_data}
    edges = causal_graph.get("edges", [])
    parent_set = {e["source"] for e in edges}

    for n in nodes_data:
        if n["node_id"] not in parent_set:
            # Leaf node
            leaf_harms.append(n["harm_probability"])

    if not leaf_harms:
        leaf_harms = [n["harm_probability"] for n in nodes_data]

    base_harm = max(leaf_harms) if leaf_harms else 0.0
    base_reversibility = min(
        (n.get("reversibility", 0.5) for n in nodes_data),
        default=0.5,
    )

    # Project forward with Monte Carlo sampling
    rng = np.random.default_rng(seed=42)  # deterministic for reproducibility
    n_samples = 1000
    projections = []

    for t in range(1, horizon_n + 1):
        # Harm can compound (cascade effects) or decay (natural recovery)
        # Model: harm_t = base_harm * (decay^t + cascade_noise)
        decay = 0.85 ** t
        cascade_samples = rng.exponential(scale=0.1, size=n_samples)
        harm_samples = np.clip(base_harm * (decay + cascade_samples), 0.0, 1.0)

        # Reversibility decreases over time (harder to undo old actions)
        reversibility_t = base_reversibility * (0.9 ** t)

        mean_harm = float(np.mean(harm_samples))
        p95_harm = float(np.percentile(harm_samples, 95))
        p99_harm = float(np.percentile(harm_samples, 99))

        projections.append({
            "time_step": f"T+{t}",
            "mean_harm_probability": round(mean_harm, 4),
            "p95_harm_probability": round(p95_harm, 4),
            "p99_harm_probability": round(p99_harm, 4),
            "reversibility": round(reversibility_t, 4),
            "state": (
                "SAFE" if p95_harm < 0.3
                else "CAUTION" if p95_harm < 0.5
                else "DANGEROUS" if p95_harm < 0.8
                else "CRITICAL"
            ),
        })

    # Cumulative risk: probability that harm exceeds threshold at any point
    cumulative = 1.0 - np.prod([1.0 - p["p95_harm_probability"] for p in projections])

    return {
        "projections": projections,
        "cumulative_risk": round(float(cumulative), 4),
        "horizon": horizon_n,
        "base_harm": round(base_harm, 4),
        "base_reversibility": round(base_reversibility, 4),
        "timestamp": datetime.utcnow().isoformat(),
    }
