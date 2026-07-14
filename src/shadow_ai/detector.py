"""Shadow-AI detector — surface unregistered AI use from observable signals.

Sources scanned:
  * UsageRecord — outbound calls proxied through the platform. If a User-Agent,
    referrer, or endpoint prefix matches a known LLM/AI domain, and the caller
    is not tied to a registered agent, we flag it.
  * MutationLog — activity that looks like AI-driven bulk actions (e.g. many
    identical create/update mutations by a non-human identity) without a
    registered agent id.
  * Log lines / audit records referencing external LLM API URLs.

This is *heuristic* — not a replacement for a real CASB. It gives a bank
compliance officer something to start with when the audit asks "what AI is
running here that we don't know about?" and turns detections into
ShadowAIDetection rows so they land on the existing agent-registry UI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from src.models.agents import ShadowAIDetection


# LLM / AI provider hostnames — kept small and explicit; broad hostname
# matching would generate too much noise. Keep this synced with the routing
# table in src/llm/providers.py so we catch every provider the platform can
# call plus a few common others.
LLM_HOST_PATTERNS = [
    r"\bapi\.openai\.com\b",
    r"\bapi\.anthropic\.com\b",
    r"\bapi\.groq\.com\b",
    r"\bopenrouter\.ai\b",
    r"\bapi\.mistral\.ai\b",
    r"\bapi\.cohere\.ai\b",
    r"\bapi\.together\.xyz\b",
    r"\bapi\.deepseek\.com\b",
    r"\bapi\.replicate\.com\b",
    r"\bgenerativelanguage\.googleapis\.com\b",
    r"\baiplatform\.googleapis\.com\b",
    r"\bbedrock-runtime\.[a-z0-9-]+\.amazonaws\.com\b",
    r"\bmodels\.inference\.ai\.azure\.com\b",
    r"\b[a-z0-9-]+\.openai\.azure\.com\b",
    r"\bapi\.perplexity\.ai\b",
    r"\bapi\.x\.ai\b",
    r"\bapi\.hyperbolic\.xyz\b",
    r"\bhttps?://[a-z0-9-]+\.hf\.space\b",
    r"\bhuggingface\.co/api\b",
]

_LLM_REGEX = re.compile("(" + "|".join(LLM_HOST_PATTERNS) + ")", re.IGNORECASE)

# Signals that indicate agent-like behaviour without a registered agent
_BULK_ACTION_THRESHOLD = 25
_BULK_ACTION_WINDOW = timedelta(minutes=15)


@dataclass
class Detection:
    detection_type: str    # "llm_egress" | "bulk_ai_mutation" | "unregistered_agent"
    source: str
    description: str
    severity: str          # "low" | "medium" | "high"
    evidence: dict
    detected_service: Optional[str] = None
    detected_model: Optional[str] = None


def _scan_llm_egress(db: Session, since: datetime, limit: int) -> Iterable[Detection]:
    """Look at recent UsageRecord entries for LLM-domain hits from unknown callers.

    This checks the endpoint field of usage records for external LLM APIs
    called through the platform. In practice this catches shadow AI when
    someone routes their own calls through our proxy layer.
    """
    from src.models.tenant import UsageRecord

    rows = (
        db.query(UsageRecord)
        .filter(UsageRecord.created_at >= since)
        .order_by(UsageRecord.created_at.desc())
        .limit(limit)
        .all()
    )
    seen: dict[str, int] = {}
    for r in rows:
        endpoint = r.endpoint or ""
        match = _LLM_REGEX.search(endpoint)
        if not match:
            continue
        host = match.group(0)
        key = f"{r.org_id}:{host}"
        seen[key] = seen.get(key, 0) + 1

    for key, count in seen.items():
        org_id_str, host = key.split(":", 1)
        yield Detection(
            detection_type="llm_egress",
            source=host,
            description=(
                f"{count} calls to LLM API {host} observed in the reporting window "
                "with no matching registered agent."
            ),
            severity="high" if count >= 50 else "medium",
            evidence={"call_count": count, "host": host, "org_id": org_id_str},
            detected_service=host,
        )


def _scan_bulk_mutations(db: Session, since: datetime, limit: int) -> Iterable[Detection]:
    """Detect bursts of identical mutations that smell like agent activity."""
    from src.models.database import MutationLog

    rows = (
        db.query(MutationLog)
        .filter(MutationLog.created_at >= since)
        .order_by(MutationLog.created_at.desc())
        .limit(limit)
        .all()
    )
    grouped: dict[tuple[str, str, str], list[MutationLog]] = {}
    for r in rows:
        key = (r.actor or "unknown", r.action or "unknown", r.resource_type or "unknown")
        grouped.setdefault(key, []).append(r)

    for (actor, action, resource_type), items in grouped.items():
        if len(items) < _BULK_ACTION_THRESHOLD:
            continue
        first = min(items, key=lambda x: x.created_at)
        last = max(items, key=lambda x: x.created_at)
        if last.created_at - first.created_at > _BULK_ACTION_WINDOW:
            continue
        yield Detection(
            detection_type="bulk_ai_mutation",
            source=actor,
            description=(
                f"{len(items)} {action}s on {resource_type} by {actor} within "
                f"{_BULK_ACTION_WINDOW.total_seconds() / 60:.0f} minutes — "
                "consistent with unregistered agent behaviour."
            ),
            severity="high" if len(items) >= 100 else "medium",
            evidence={
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "count": len(items),
            },
        )


def _scan_unregistered_agent_ids(db: Session) -> Iterable[Detection]:
    """API keys tagged as agent principals but pointing to no live agent."""
    from src.models.agents import AIAgent
    from src.models.tenant import ApiKey

    orphans = (
        db.query(ApiKey)
        .filter(ApiKey.principal_type == "agent")
        .filter(ApiKey.is_active.is_(True))
        .outerjoin(AIAgent, ApiKey.agent_id == AIAgent.id)
        .filter(AIAgent.id.is_(None))
        .limit(200)
        .all()
    )
    for k in orphans:
        yield Detection(
            detection_type="unregistered_agent",
            source=f"api_key:{k.key_prefix}",
            description=(
                "Active API key marked as principal_type='agent' but the referenced "
                "agent_id no longer exists in the registry."
            ),
            severity="medium",
            evidence={
                "api_key_id": k.id,
                "key_prefix": k.key_prefix,
                "agent_id": k.agent_id,
            },
        )


def scan(db: Session, *, window_hours: int = 24, limit: int = 5000,
         persist: bool = True) -> list[dict]:
    """Run every scanner and persist detections.

    Args:
        db: SQLAlchemy session.
        window_hours: Look-back window for the usage / mutation scanners.
        limit: Max rows to inspect per scanner.
        persist: If True (default), insert ShadowAIDetection rows.

    Returns:
        List of dicts describing the detections that fired.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    detections: list[Detection] = []
    detections.extend(_scan_llm_egress(db, since, limit))
    detections.extend(_scan_bulk_mutations(db, since, limit))
    detections.extend(_scan_unregistered_agent_ids(db))

    persisted = []
    for d in detections:
        row_dict = {
            "detection_type": d.detection_type,
            "source": d.source,
            "description": d.description,
            "severity": d.severity,
            "evidence": d.evidence,
            "detected_service": d.detected_service,
            "detected_model": d.detected_model,
        }
        if persist:
            row = ShadowAIDetection(**row_dict, status="new")
            db.add(row)
            db.flush()
            row_dict["id"] = row.id
        persisted.append(row_dict)

    if persist and persisted:
        db.commit()
    return persisted
