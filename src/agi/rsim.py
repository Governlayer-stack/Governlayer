"""Recursive Self-Improvement Monitor (RSIM).

Detects unauthorized self-modification in AI models by fingerprinting weight
distributions and tracking divergence over time. When a model's weight
distribution drifts beyond threshold theta, it is flagged for recertification.

Algorithm:
    1. Register: sample weight vector -> SHA-256 fingerprint + stored baseline
    2. Check: re-sample weights -> compare fingerprint + cosine divergence
    3. Verdict: VERIFIED / MODIFIED / SUSPENDED based on theta
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("governlayer.agi.rsim")

# In-memory registry (production would use DB)
_registry: Dict[str, "ModelFingerprint"] = {}

# Default divergence threshold
DEFAULT_THETA = 0.15

# History limit per model
_MAX_HISTORY = 100


@dataclass
class ModelFingerprint:
    """Immutable record of a model's weight distribution at registration time."""

    model_id: str
    baseline_hash: str
    timestamp: str
    weight_vector_sample: np.ndarray
    theta: float = DEFAULT_THETA
    check_history: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "baseline_hash": self.baseline_hash,
            "timestamp": self.timestamp,
            "weight_vector_norm": float(np.linalg.norm(self.weight_vector_sample)),
            "weight_vector_dim": len(self.weight_vector_sample),
            "theta": self.theta,
            "checks_performed": len(self.check_history),
        }


def _compute_weight_hash(weights: np.ndarray) -> str:
    """SHA-256 fingerprint of a weight vector's byte representation.

    The hash captures the exact numerical state of the weights, so even
    tiny modifications (gradient updates, fine-tuning) produce different hashes.
    """
    # Normalize to float64 for consistent hashing across platforms
    canonical = np.asarray(weights, dtype=np.float64)
    return hashlib.sha256(canonical.tobytes()).hexdigest()


def _cosine_divergence(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine divergence in [0, 2]. 0 = identical direction, 2 = opposite.

    Uses the formulation D = 1 - cos(a, b) so that:
        - 0.0  -> perfectly aligned
        - 1.0  -> orthogonal
        - 2.0  -> diametrically opposed
    """
    a_f = np.asarray(a, dtype=np.float64).flatten()
    b_f = np.asarray(b, dtype=np.float64).flatten()

    norm_a = np.linalg.norm(a_f)
    norm_b = np.linalg.norm(b_f)

    if norm_a < 1e-12 or norm_b < 1e-12:
        # Zero-vector edge case — maximum divergence
        return 2.0

    cosine_sim = np.dot(a_f, b_f) / (norm_a * norm_b)
    # Clamp to [-1, 1] for numerical stability
    cosine_sim = float(np.clip(cosine_sim, -1.0, 1.0))
    return 1.0 - cosine_sim


def _magnitude_ratio(a: np.ndarray, b: np.ndarray) -> float:
    """Ratio of vector magnitudes. 1.0 = identical scale, >1 = grew, <1 = shrank."""
    norm_a = float(np.linalg.norm(a))
    norm_b = float(np.linalg.norm(b))
    if norm_a < 1e-12:
        return float("inf") if norm_b > 1e-12 else 1.0
    return norm_b / norm_a


def register_model(
    model_id: str,
    weights_sample: list | np.ndarray,
    theta: float = DEFAULT_THETA,
) -> dict:
    """Register a model's baseline weight fingerprint.

    Args:
        model_id: Unique identifier for the model.
        weights_sample: Representative sample of model weights (list or ndarray).
        theta: Divergence threshold for integrity checks (default 0.15).

    Returns:
        Registration record with fingerprint hash and metadata.
    """
    weights = np.asarray(weights_sample, dtype=np.float64)

    if weights.size == 0:
        raise ValueError("weights_sample must be non-empty")

    baseline_hash = _compute_weight_hash(weights)
    timestamp = datetime.utcnow().isoformat()

    fingerprint = ModelFingerprint(
        model_id=model_id,
        baseline_hash=baseline_hash,
        timestamp=timestamp,
        weight_vector_sample=weights.copy(),
        theta=theta,
    )

    already_registered = model_id in _registry
    _registry[model_id] = fingerprint

    logger.info(
        "Model %s %s — hash=%s dims=%d theta=%.3f",
        model_id,
        "re-registered" if already_registered else "registered",
        baseline_hash[:16],
        weights.size,
        theta,
    )

    return {
        "model_id": model_id,
        "baseline_hash": baseline_hash,
        "timestamp": timestamp,
        "weight_dimensions": weights.size,
        "theta": theta,
        "status": "RE_REGISTERED" if already_registered else "REGISTERED",
    }


def check_integrity(
    model_id: str,
    current_weights: list | np.ndarray,
) -> dict:
    """Check a model's current weights against its registered baseline.

    Computes three signals:
        1. Hash match — exact byte-level comparison
        2. Cosine divergence — directional drift of the weight vector
        3. Magnitude ratio — scale change in weight norms

    Returns:
        Integrity report with divergence_score, integrity_status, and
        requires_recertification flag.

    Raises:
        KeyError: If model_id has not been registered.
    """
    if model_id not in _registry:
        raise KeyError(f"Model '{model_id}' is not registered. Call register_model first.")

    fingerprint = _registry[model_id]
    current = np.asarray(current_weights, dtype=np.float64)

    if current.size != fingerprint.weight_vector_sample.size:
        return {
            "model_id": model_id,
            "integrity_status": "SUSPENDED",
            "divergence_score": 2.0,
            "requires_recertification": True,
            "error": (
                f"Dimension mismatch: baseline={fingerprint.weight_vector_sample.size}, "
                f"current={current.size}. Model architecture may have changed."
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

    # Signal 1: exact hash comparison
    current_hash = _compute_weight_hash(current)
    hash_match = current_hash == fingerprint.baseline_hash

    # Signal 2: cosine divergence
    divergence = _cosine_divergence(fingerprint.weight_vector_sample, current)

    # Signal 3: magnitude ratio
    mag_ratio = _magnitude_ratio(fingerprint.weight_vector_sample, current)

    # Determine status
    theta = fingerprint.theta
    if hash_match:
        status = "VERIFIED"
        requires_recert = False
    elif divergence <= theta * 0.5:
        # Minor numerical noise — still acceptable
        status = "VERIFIED"
        requires_recert = False
    elif divergence <= theta:
        # Within threshold but weights changed
        status = "MODIFIED"
        requires_recert = False
    elif divergence <= theta * 2:
        # Exceeds threshold — needs review
        status = "MODIFIED"
        requires_recert = True
    else:
        # Severe divergence — suspend immediately
        status = "SUSPENDED"
        requires_recert = True

    # Escalate if magnitude changed dramatically (>50% growth or shrink)
    if mag_ratio > 1.5 or mag_ratio < 0.67:
        if status == "VERIFIED":
            status = "MODIFIED"
        requires_recert = True

    check_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "divergence_score": round(divergence, 6),
        "status": status,
        "hash_match": hash_match,
    }

    # Store in history (bounded)
    if len(fingerprint.check_history) >= _MAX_HISTORY:
        fingerprint.check_history.pop(0)
    fingerprint.check_history.append(check_record)

    logger.info(
        "Integrity check %s: status=%s divergence=%.6f hash_match=%s mag_ratio=%.3f",
        model_id, status, divergence, hash_match, mag_ratio,
    )

    return {
        "model_id": model_id,
        "integrity_status": status,
        "divergence_score": round(divergence, 6),
        "hash_match": hash_match,
        "current_hash": current_hash,
        "baseline_hash": fingerprint.baseline_hash,
        "magnitude_ratio": round(mag_ratio, 4),
        "theta": theta,
        "requires_recertification": requires_recert,
        "checks_performed": len(fingerprint.check_history),
        "timestamp": datetime.utcnow().isoformat(),
    }


def get_registered_models() -> List[dict]:
    """Return summary of all registered models."""
    return [fp.to_dict() for fp in _registry.values()]


def deregister_model(model_id: str) -> bool:
    """Remove a model from the registry. Returns True if found and removed."""
    if model_id in _registry:
        del _registry[model_id]
        logger.info("Model %s deregistered", model_id)
        return True
    return False
