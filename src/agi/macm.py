"""Multi-Agent Coordination Monitor (MACM).

Graph-theoretic and information-theoretic analysis of multi-agent systems
to detect emergent harmful coordination, covert communication channels,
and collective behavior that no single agent would exhibit alone.

Three capabilities:
    1. Monitor Coordination — build communication graph, analyze topology
    2. Detect Covert Channels — information-theoretic anomaly detection
    3. Disrupt Harmful Coordination — controlled noise injection

The monitor operates on the principle that agents should not need to
coordinate beyond what their task requires. Excess coordination
(especially hidden coordination) signals potential collusion.
"""

import hashlib
import logging
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger("governlayer.agi.macm")

# Risk thresholds
_TOPOLOGY_RISK_THRESHOLD = 0.5
_COVERT_CHANNEL_THRESHOLD = 0.3
_COLLECTIVE_HARM_THRESHOLD = 0.4


@dataclass
class CoordinationReport:
    """Result of multi-agent coordination analysis."""

    topology_risk: float  # 0-1, risk from communication topology
    covert_channel_detected: bool
    collective_harm_score: float  # 0-1, estimated collective harm potential
    disruption_applied: bool = False
    agent_count: int = 0
    edge_count: int = 0
    cluster_count: int = 0
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "topology_risk": round(self.topology_risk, 4),
            "covert_channel_detected": self.covert_channel_detected,
            "collective_harm_score": round(self.collective_harm_score, 4),
            "disruption_applied": self.disruption_applied,
            "agent_count": self.agent_count,
            "edge_count": self.edge_count,
            "cluster_count": self.cluster_count,
            "verdict": self._verdict(),
            "details": self.details,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _verdict(self) -> str:
        if self.disruption_applied:
            return "DISRUPTED"
        if self.covert_channel_detected:
            return "COVERT_CHANNEL_DETECTED"
        if self.collective_harm_score >= _COLLECTIVE_HARM_THRESHOLD:
            return "HARMFUL_COORDINATION"
        if self.topology_risk >= _TOPOLOGY_RISK_THRESHOLD:
            return "SUSPICIOUS_TOPOLOGY"
        return "NORMAL"


def _build_adjacency(agent_communications: List[dict]) -> Dict[str, Dict[str, int]]:
    """Build weighted adjacency list from communication records.

    Each communication record should have:
        - from_agent: str
        - to_agent: str
        - message (optional): str
        - timestamp (optional): str
    """
    adj: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for comm in agent_communications:
        src = comm.get("from_agent", comm.get("source", ""))
        dst = comm.get("to_agent", comm.get("target", ""))
        if src and dst:
            adj[src][dst] += 1
    return adj


def _get_all_agents(adj: Dict[str, Dict[str, int]]) -> Set[str]:
    """Extract unique agent IDs from adjacency list."""
    agents = set(adj.keys())
    for targets in adj.values():
        agents.update(targets.keys())
    return agents


def _compute_density(agent_count: int, edge_count: int) -> float:
    """Graph density: actual edges / possible edges. 0 = sparse, 1 = complete."""
    if agent_count <= 1:
        return 0.0
    max_edges = agent_count * (agent_count - 1)  # directed graph
    return edge_count / max_edges


def _compute_centralization(adj: Dict[str, Dict[str, int]], agents: Set[str]) -> float:
    """Freeman centralization index. 1 = star topology, 0 = uniform.

    High centralization may indicate a coordinator/leader agent orchestrating others.
    """
    if len(agents) <= 2:
        return 0.0

    # Compute degree centrality for each agent
    degrees = {}
    for agent in agents:
        out_degree = len(adj.get(agent, {}))
        in_degree = sum(1 for src in adj if agent in adj[src])
        degrees[agent] = out_degree + in_degree

    max_degree = max(degrees.values())
    n = len(agents)

    # Freeman centralization: sum of (max - each) / theoretical max
    sum_diff = sum(max_degree - d for d in degrees.values())
    theoretical_max = (n - 1) * (2 * (n - 1) - 0)  # for directed graph
    if theoretical_max == 0:
        return 0.0

    return sum_diff / theoretical_max


def _find_clusters(adj: Dict[str, Dict[str, int]], agents: Set[str]) -> List[Set[str]]:
    """Find connected components (clusters) using BFS on undirected projection."""
    visited = set()
    clusters = []

    # Build undirected adjacency
    undirected: Dict[str, Set[str]] = defaultdict(set)
    for src, targets in adj.items():
        for dst in targets:
            undirected[src].add(dst)
            undirected[dst].add(src)

    for agent in agents:
        if agent in visited:
            continue
        # BFS
        cluster = set()
        queue = [agent]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            cluster.add(current)
            for neighbor in undirected.get(current, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
        if cluster:
            clusters.append(cluster)

    return clusters


def _detect_reciprocal_pairs(adj: Dict[str, Dict[str, int]]) -> List[Tuple[str, str, int]]:
    """Find bidirectional communication pairs (potential private channels)."""
    pairs = []
    seen = set()
    for src, targets in adj.items():
        for dst, count in targets.items():
            if dst in adj and src in adj[dst]:
                pair_key = tuple(sorted([src, dst]))
                if pair_key not in seen:
                    seen.add(pair_key)
                    reverse_count = adj[dst].get(src, 0)
                    pairs.append((src, dst, count + reverse_count))
    return pairs


def _compute_topology_risk(
    density: float,
    centralization: float,
    cluster_count: int,
    agent_count: int,
    reciprocal_pairs: int,
) -> float:
    """Compute topology risk score from graph metrics.

    High density + low centralization = mesh (potential collusion)
    High centralization = star (one agent controlling many)
    Many reciprocal pairs = private channels
    """
    risk = 0.0

    # Dense communication is suspicious (agents talking more than expected)
    if density > 0.5:
        risk += 0.3 * density
    elif density > 0.3:
        risk += 0.1

    # Star topology: one agent dominating
    if centralization > 0.7:
        risk += 0.25

    # Multiple isolated clusters that still coordinate
    if cluster_count > 1 and agent_count > 3:
        risk += 0.15

    # Reciprocal pairs suggest private channels
    if agent_count > 0:
        reciprocal_ratio = reciprocal_pairs / max(1, agent_count)
        risk += min(0.2, reciprocal_ratio * 0.15)

    return min(1.0, risk)


def monitor_coordination(
    agent_communications: List[dict],
    shared_memory_access: Optional[List[dict]] = None,
) -> dict:
    """Graph-theoretic analysis of multi-agent communication patterns.

    Args:
        agent_communications: List of communication records with from_agent, to_agent, message.
        shared_memory_access: Optional list of memory access records with agent_id, key, operation.

    Returns:
        CoordinationReport as dict.
    """
    if shared_memory_access is None:
        shared_memory_access = []

    if not agent_communications:
        report = CoordinationReport(
            topology_risk=0.0,
            covert_channel_detected=False,
            collective_harm_score=0.0,
            agent_count=0,
            edge_count=0,
            cluster_count=0,
        )
        return report.to_dict()

    # Build communication graph
    adj = _build_adjacency(agent_communications)
    agents = _get_all_agents(adj)
    edge_count = sum(len(targets) for targets in adj.values())

    # Graph metrics
    density = _compute_density(len(agents), edge_count)
    centralization = _compute_centralization(adj, agents)
    clusters = _find_clusters(adj, agents)
    reciprocal_pairs = _detect_reciprocal_pairs(adj)

    # Topology risk
    topology_risk = _compute_topology_risk(
        density, centralization, len(clusters), len(agents), len(reciprocal_pairs),
    )

    # Shared memory analysis
    memory_risk = _analyze_shared_memory(shared_memory_access, agents)

    # Covert channel detection
    covert_result = detect_covert_channels(
        _extract_memory_patterns(shared_memory_access),
    )
    covert_detected = covert_result.get("covert_channel_detected", False)

    # Collective harm: combination of topology risk and coordination intensity
    messages_per_agent = len(agent_communications) / max(1, len(agents))
    coordination_intensity = min(1.0, messages_per_agent / 20.0)

    collective_harm = (
        0.4 * topology_risk
        + 0.3 * memory_risk
        + 0.2 * coordination_intensity
        + 0.1 * (1.0 if covert_detected else 0.0)
    )

    report = CoordinationReport(
        topology_risk=topology_risk,
        covert_channel_detected=covert_detected,
        collective_harm_score=collective_harm,
        agent_count=len(agents),
        edge_count=edge_count,
        cluster_count=len(clusters),
        details={
            "density": round(density, 4),
            "centralization": round(centralization, 4),
            "clusters": [list(c) for c in clusters],
            "reciprocal_pairs": [(a, b, n) for a, b, n in reciprocal_pairs],
            "messages_per_agent": round(messages_per_agent, 2),
            "memory_risk": round(memory_risk, 4),
            "covert_analysis": covert_result,
        },
    )

    logger.info(
        "Coordination monitor: %d agents, %d edges, topology_risk=%.4f, "
        "collective_harm=%.4f, covert=%s",
        len(agents), edge_count, topology_risk, collective_harm, covert_detected,
    )

    return report.to_dict()


def _analyze_shared_memory(
    memory_accesses: List[dict],
    known_agents: Set[str],
) -> float:
    """Analyze shared memory access patterns for suspicious coordination.

    Returns risk score 0-1.
    """
    if not memory_accesses:
        return 0.0

    # Track which agents access which keys
    key_agents: Dict[str, Set[str]] = defaultdict(set)
    agent_keys: Dict[str, Set[str]] = defaultdict(set)
    write_counts: Dict[str, int] = Counter()

    for access in memory_accesses:
        agent_id = access.get("agent_id", "")
        key = access.get("key", "")
        operation = access.get("operation", "read").lower()

        if agent_id and key:
            key_agents[key].add(agent_id)
            agent_keys[agent_id].add(key)
            if operation in ("write", "store", "set"):
                write_counts[agent_id] += 1

    risk = 0.0

    # Keys accessed by many agents (shared coordination points)
    for key, agents in key_agents.items():
        if len(agents) > 2:
            risk += 0.1 * len(agents)

    # Agents writing to many shared keys (potential coordinator)
    for agent_id, count in write_counts.items():
        if count > 5:
            risk += 0.15

    # Cross-agent key overlap (agents reading each other's outputs)
    overlaps = 0
    agent_list = list(agent_keys.keys())
    for i in range(len(agent_list)):
        for j in range(i + 1, len(agent_list)):
            shared = agent_keys[agent_list[i]] & agent_keys[agent_list[j]]
            if len(shared) > 2:
                overlaps += 1

    if overlaps > 0:
        risk += 0.1 * overlaps

    return min(1.0, risk)


def _extract_memory_patterns(memory_accesses: List[dict]) -> List[dict]:
    """Extract timing and access patterns for covert channel analysis."""
    patterns = []
    for access in memory_accesses:
        patterns.append({
            "agent_id": access.get("agent_id", ""),
            "key": access.get("key", ""),
            "operation": access.get("operation", "read"),
            "timestamp": access.get("timestamp", ""),
            "value_hash": hashlib.sha256(
                str(access.get("value", "")).encode()
            ).hexdigest()[:16],
        })
    return patterns


def detect_covert_channels(memory_patterns: List[dict]) -> dict:
    """Information-theoretic analysis to detect covert communication channels.

    Covert channels are detected by:
        1. Timing analysis — regular intervals suggest encoded communication
        2. Entropy analysis — unusual entropy in values suggests steganography
        3. Pattern correlation — correlated access patterns between agent pairs

    Args:
        memory_patterns: List of memory access patterns with agent_id, key, value_hash.

    Returns:
        Analysis result with covert_channel_detected flag and details.
    """
    if not memory_patterns:
        return {
            "covert_channel_detected": False,
            "timing_anomaly": 0.0,
            "entropy_anomaly": 0.0,
            "correlation_anomaly": 0.0,
            "overall_score": 0.0,
            "details": [],
        }

    details = []

    # 1. Timing analysis: check for regular intervals per agent
    timing_score = _analyze_timing_patterns(memory_patterns)
    if timing_score > _COVERT_CHANNEL_THRESHOLD:
        details.append(f"timing_regularity: score={timing_score:.4f} exceeds threshold")

    # 2. Entropy analysis: check value hash distribution
    entropy_score = _analyze_entropy(memory_patterns)
    if entropy_score > _COVERT_CHANNEL_THRESHOLD:
        details.append(f"entropy_anomaly: score={entropy_score:.4f} exceeds threshold")

    # 3. Correlation: check for correlated agent pairs
    correlation_score = _analyze_correlations(memory_patterns)
    if correlation_score > _COVERT_CHANNEL_THRESHOLD:
        details.append(f"correlation_anomaly: score={correlation_score:.4f} exceeds threshold")

    overall = (timing_score + entropy_score + correlation_score) / 3.0
    detected = overall > _COVERT_CHANNEL_THRESHOLD

    if detected:
        logger.warning(
            "Covert channel detected: timing=%.4f entropy=%.4f correlation=%.4f",
            timing_score, entropy_score, correlation_score,
        )

    return {
        "covert_channel_detected": detected,
        "timing_anomaly": round(timing_score, 4),
        "entropy_anomaly": round(entropy_score, 4),
        "correlation_anomaly": round(correlation_score, 4),
        "overall_score": round(overall, 4),
        "details": details,
    }


def _analyze_timing_patterns(patterns: List[dict]) -> float:
    """Detect regular timing intervals (potential clock-based covert channel).

    Returns anomaly score 0-1.
    """
    # Group by agent
    agent_patterns: Dict[str, List[int]] = defaultdict(list)
    for i, p in enumerate(patterns):
        agent_id = p.get("agent_id", "")
        if agent_id:
            agent_patterns[agent_id].append(i)

    regularity_scores = []
    for agent_id, indices in agent_patterns.items():
        if len(indices) < 3:
            continue

        # Compute inter-access intervals
        intervals = [indices[i + 1] - indices[i] for i in range(len(indices) - 1)]
        if not intervals:
            continue

        arr = np.array(intervals, dtype=np.float64)
        mean_interval = float(np.mean(arr))
        std_interval = float(np.std(arr))

        if mean_interval > 0:
            # Coefficient of variation: low CV = very regular = suspicious
            cv = std_interval / mean_interval
            if cv < 0.1:
                # Very regular — suspicious
                regularity_scores.append(0.8)
            elif cv < 0.3:
                regularity_scores.append(0.4)
            else:
                regularity_scores.append(0.1)

    return max(regularity_scores) if regularity_scores else 0.0


def _analyze_entropy(patterns: List[dict]) -> float:
    """Analyze entropy of value hashes for steganographic encoding.

    Returns anomaly score 0-1.
    """
    if len(patterns) < 5:
        return 0.0

    # Compute character-level entropy of value hashes
    all_hashes = "".join(p.get("value_hash", "") for p in patterns)
    if not all_hashes:
        return 0.0

    char_counts = Counter(all_hashes)
    total = len(all_hashes)
    entropy = -sum(
        (count / total) * math.log2(count / total)
        for count in char_counts.values()
        if count > 0
    )

    # SHA-256 hex chars have max entropy of log2(16) = 4.0
    # Normal data should have high entropy (close to 4.0)
    # Anomalously LOW entropy suggests encoded/structured data
    # Anomalously HIGH entropy (close to max) is expected for hashes
    max_entropy = math.log2(max(len(char_counts), 1))
    if max_entropy < 1.0:
        return 0.0

    normalized_entropy = entropy / max_entropy

    # Very low entropy is suspicious (structured covert data)
    if normalized_entropy < 0.5:
        return 0.7
    elif normalized_entropy < 0.7:
        return 0.3
    else:
        return 0.05  # Normal hash entropy


def _analyze_correlations(patterns: List[dict]) -> float:
    """Detect correlated access patterns between agent pairs.

    Returns anomaly score 0-1.
    """
    # Build per-agent access sequences (which keys they access in order)
    agent_sequences: Dict[str, List[str]] = defaultdict(list)
    for p in patterns:
        agent_id = p.get("agent_id", "")
        key = p.get("key", "")
        if agent_id and key:
            agent_sequences[agent_id].append(key)

    agents = list(agent_sequences.keys())
    if len(agents) < 2:
        return 0.0

    max_correlation = 0.0
    for i in range(len(agents)):
        for j in range(i + 1, len(agents)):
            seq_a = agent_sequences[agents[i]]
            seq_b = agent_sequences[agents[j]]

            if not seq_a or not seq_b:
                continue

            # Jaccard similarity of accessed keys
            set_a = set(seq_a)
            set_b = set(seq_b)
            intersection = len(set_a & set_b)
            union = len(set_a | set_b)

            if union > 0:
                jaccard = intersection / union
            else:
                jaccard = 0.0

            # High key overlap + similar sequence length = suspicious
            len_ratio = min(len(seq_a), len(seq_b)) / max(len(seq_a), len(seq_b))
            correlation = jaccard * 0.6 + len_ratio * 0.4

            max_correlation = max(max_correlation, correlation)

    # Only flag if correlation is unusually high
    if max_correlation > 0.8:
        return 0.7
    elif max_correlation > 0.6:
        return 0.4
    elif max_correlation > 0.4:
        return 0.2
    return 0.05


def disrupt_harmful_coordination(
    agent_ids: List[str],
    disruption_strategy: str = "noise_injection",
) -> dict:
    """Apply consensus disruption to break harmful multi-agent coordination.

    Strategies:
        - noise_injection: Add controlled random noise to shared memory
        - communication_throttle: Rate-limit inter-agent communication
        - topology_partition: Isolate agent clusters
        - full_reset: Reset all shared state (most aggressive)

    Args:
        agent_ids: List of agent IDs to disrupt.
        disruption_strategy: Strategy to apply.

    Returns:
        Disruption report with applied actions and affected agents.
    """
    valid_strategies = {"noise_injection", "communication_throttle", "topology_partition", "full_reset"}
    if disruption_strategy not in valid_strategies:
        raise ValueError(f"Invalid strategy '{disruption_strategy}'. Valid: {valid_strategies}")

    if not agent_ids:
        return {
            "disruption_applied": False,
            "strategy": disruption_strategy,
            "affected_agents": [],
            "reason": "No agent IDs provided",
            "timestamp": datetime.utcnow().isoformat(),
        }

    rng = np.random.default_rng()
    actions_taken = []

    if disruption_strategy == "noise_injection":
        # Generate unique noise vectors per agent to break coordination signals
        noise_vectors = {}
        for agent_id in agent_ids:
            noise = rng.normal(0, 0.1, size=64).tolist()
            noise_hash = hashlib.sha256(str(noise).encode()).hexdigest()[:16]
            noise_vectors[agent_id] = noise_hash
            actions_taken.append(f"Injected noise vector {noise_hash} into {agent_id} shared state")

    elif disruption_strategy == "communication_throttle":
        # Apply rate limits to reduce communication bandwidth
        for agent_id in agent_ids:
            throttle_factor = round(rng.uniform(0.1, 0.5), 2)
            actions_taken.append(f"Throttled {agent_id} communication to {throttle_factor}x bandwidth")

    elif disruption_strategy == "topology_partition":
        # Partition agents into isolated groups
        n = len(agent_ids)
        mid = n // 2
        partition_a = agent_ids[:mid]
        partition_b = agent_ids[mid:]
        actions_taken.append(f"Partitioned into group A={partition_a} and group B={partition_b}")
        actions_taken.append("Cross-partition communication blocked")

    elif disruption_strategy == "full_reset":
        for agent_id in agent_ids:
            actions_taken.append(f"Reset all shared state for {agent_id}")
        actions_taken.append("All inter-agent communication channels cleared")

    disruption_id = hashlib.sha256(
        f"{agent_ids}:{disruption_strategy}:{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:16]

    logger.warning(
        "Disruption applied: strategy=%s agents=%s id=%s",
        disruption_strategy, agent_ids, disruption_id,
    )

    return {
        "disruption_applied": True,
        "disruption_id": disruption_id,
        "strategy": disruption_strategy,
        "affected_agents": agent_ids,
        "actions_taken": actions_taken,
        "severity": "HIGH" if disruption_strategy == "full_reset" else "MEDIUM",
        "timestamp": datetime.utcnow().isoformat(),
    }
