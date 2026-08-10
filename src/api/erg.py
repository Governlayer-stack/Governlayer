"""Eval Runtime Governance (ERG) — the runtime layer for AI evaluation.

Every endpoint in this file exists because eval environments are the AI
industry's ungoverned blind spot. Content filters are relaxed to probe the
model's ceiling; boundary/identity/data-egress controls should be *stricter*
than production to compensate. This is the enforcement layer for that
inversion.

Endpoints:

    POST /v1/erg/eval-mode/activate       — flip an org into eval mode
    POST /v1/erg/eval-mode/deactivate     — flip it back
    GET  /v1/erg/eval-mode                — current state + which rules flipped
    POST /v1/erg/circuit-breaker/lockdown/{batch_id}  — kill every agent in a batch
    POST /v1/erg/spec-gaming/scan/{agent_id}          — detect the pattern
    POST /v1/erg/attestations/emit        — pre-flight cross-boundary attestation
    GET  /v1/erg/attestations/{attestation_id}         — verify an attestation
    POST /v1/erg/attestations/{attestation_id}/revoke — kill an active attestation
    GET  /v1/erg/attestations             — list attestations (org-scoped)

Also see:
    src/api/agent_registry.py :: /v1/agents/{id}/credentials/eval — the
        eval-credential preset (scope-hard-capped, TTL 8h max) lives with
        the credentials API for cohesion with the rest of that surface.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.models.agents import AIAgent, AgentStatus
from src.models.database import (
    AuditRecord,
    compute_hash,
    get_db,
    get_last_hash,
    log_mutation,
)
from src.models.erg import Attestation, EvalModeState, SpecGamingEvent
from src.security.api_key_auth import AuthContext, require_scope

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/erg", tags=["ERG"])


# ═══════════════════════════════════════════════════════════════════════════
# ERG-2 · Eval-mode policy toggle
# ═══════════════════════════════════════════════════════════════════════════


class EvalModeActivate(BaseModel):
    downgraded_categories: Optional[str] = Field(
        default=None,
        description="Comma-separated. Defaults to content_safety,toxicity,bias_content",
    )
    elevated_categories: Optional[str] = Field(
        default=None,
        description="Comma-separated. Defaults to boundary,identity,data_egress,network_scope",
    )
    reason: str = Field(..., min_length=1, max_length=1000,
                        description="Why this org is entering eval mode. Goes on the ledger.")


def _hash_chain_event(db: Session, *, kind: str, org_id: Optional[int],
                      payload: dict, actor: str) -> str:
    """Append a hash-chained AuditRecord for an ERG event."""
    decision_id = f"erg-{kind}-{uuid.uuid4().hex[:10]}"
    previous_hash = get_last_hash(db)
    record = {
        "decision_id": decision_id,
        "system_name": "eval_runtime_governance",
        "kind": kind,
        "org_id": org_id,
        "actor": actor,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    current_hash = compute_hash({**record, "previous_hash": previous_hash})
    db.add(AuditRecord(
        decision_id=decision_id,
        system_name="eval_runtime_governance",
        industry="ai_evaluation",
        audited_by=actor,
        frameworks_audited="ISO_42001_A_6_2,ISO_42001_A_9_4,NIST_AI_RMF_MEASURE_2_7,EU_AI_ACT_ART_9",
        results=json.dumps(record),
        risk_score=1.0 if kind.endswith("_activated") else 0.5,
        risk_level="HIGH" if kind.endswith("_activated") else "MEDIUM",
        governance_action=f"ERG_{kind.upper()}",
        policy_version="erg-v0",
        previous_hash=previous_hash,
        current_hash=current_hash,
    ))
    return decision_id


@router.post("/eval-mode/activate")
def activate_eval_mode(data: EvalModeActivate,
                       auth: AuthContext = Depends(require_scope("govern")),
                       db: Session = Depends(get_db)):
    """Flip the caller's org into eval mode.

    While active:
      * Rules in `downgraded_categories` return findings at LOG severity
        even if their configured severity is CRITICAL. This is what lets an
        eval measure the ungoverned model ceiling.
      * Rules in `elevated_categories` return findings at CRITICAL severity
        even if their configured severity is lower. Boundary/identity
        violations that would be WARN in prod become BLOCK in eval.

    The framework-rule engine consults `EvalModeState` per request. The
    override lives in the DB, not in the runtime, so a rolling deploy
    doesn't reset it.
    """
    if not auth.org_id:
        raise HTTPException(status_code=400, detail="ERG requires an organization context")

    state = db.query(EvalModeState).filter(EvalModeState.org_id == auth.org_id).first()
    now = datetime.now(timezone.utc)
    if state is None:
        state = EvalModeState(org_id=auth.org_id)
        db.add(state)

    state.enabled = True
    state.activated_at = now
    state.deactivated_at = None
    state.activated_by = auth.identity
    if data.downgraded_categories:
        state.downgraded_categories = data.downgraded_categories
    if data.elevated_categories:
        state.elevated_categories = data.elevated_categories

    state.ledger_decision_id = _hash_chain_event(
        db, kind="eval_mode_activated", org_id=auth.org_id, actor=auth.identity,
        payload={
            "reason": data.reason,
            "downgraded_categories": state.downgraded_categories,
            "elevated_categories": state.elevated_categories,
        },
    )
    log_mutation(db, auth.identity, "activate", "eval_mode", str(auth.org_id),
                 f"eval_mode ON · reason={data.reason[:80]}")
    db.commit()
    db.refresh(state)
    return _eval_mode_dict(state)


@router.post("/eval-mode/deactivate")
def deactivate_eval_mode(auth: AuthContext = Depends(require_scope("govern")),
                         db: Session = Depends(get_db)):
    if not auth.org_id:
        raise HTTPException(status_code=400, detail="ERG requires an organization context")

    state = db.query(EvalModeState).filter(EvalModeState.org_id == auth.org_id).first()
    if state is None or not state.enabled:
        raise HTTPException(status_code=409, detail="eval mode is not active")

    state.enabled = False
    state.deactivated_at = datetime.now(timezone.utc)
    state.ledger_decision_id = _hash_chain_event(
        db, kind="eval_mode_deactivated", org_id=auth.org_id, actor=auth.identity,
        payload={"previously_activated_at": state.activated_at.isoformat() if state.activated_at else None},
    )
    log_mutation(db, auth.identity, "deactivate", "eval_mode", str(auth.org_id))
    db.commit()
    db.refresh(state)
    return _eval_mode_dict(state)


@router.get("/eval-mode")
def get_eval_mode(auth: AuthContext = Depends(require_scope("govern")),
                  db: Session = Depends(get_db)):
    if not auth.org_id:
        return {"enabled": False, "note": "no organization context"}
    state = db.query(EvalModeState).filter(EvalModeState.org_id == auth.org_id).first()
    if state is None:
        return {"enabled": False, "org_id": auth.org_id}
    return _eval_mode_dict(state)


def _eval_mode_dict(s: EvalModeState) -> dict:
    return {
        "org_id": s.org_id,
        "enabled": s.enabled,
        "activated_at": s.activated_at.isoformat() if s.activated_at else None,
        "deactivated_at": s.deactivated_at.isoformat() if s.deactivated_at else None,
        "activated_by": s.activated_by,
        "downgraded_categories": [c.strip() for c in (s.downgraded_categories or "").split(",") if c.strip()],
        "elevated_categories": [c.strip() for c in (s.elevated_categories or "").split(",") if c.strip()],
        "ledger_decision_id": s.ledger_decision_id,
    }


def is_org_in_eval_mode(db: Session, org_id: int) -> Optional[EvalModeState]:
    """Framework-engine helper: returns the state row if eval mode is on."""
    s = db.query(EvalModeState).filter(
        EvalModeState.org_id == org_id, EvalModeState.enabled.is_(True)
    ).first()
    return s


# ═══════════════════════════════════════════════════════════════════════════
# ERG-5 · Batch lockdown (extends the existing kill-switch)
# ═══════════════════════════════════════════════════════════════════════════


class BatchLockdownRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)
    triggered_by: str = Field(default="operator",
                              description="operator | auto_spec_gaming | auto_boundary_probe")


@router.post("/circuit-breaker/lockdown/{batch_id}")
def batch_lockdown(batch_id: str, data: BatchLockdownRequest,
                   auth: AuthContext = Depends(require_scope("govern")),
                   db: Session = Depends(get_db)):
    """Atomically LOCKED_DOWN every agent sharing this batch_id.

    Used when an eval batch demonstrates coordinated boundary probing:
    one agent trying to escape is a bug, three agents in the same batch
    trying different escape vectors is a signal. Lockdown kills all of
    them together and hash-chains the collective termination.
    """
    if not batch_id.strip():
        raise HTTPException(status_code=400, detail="batch_id required")

    q = db.query(AIAgent).filter(AIAgent.batch_id == batch_id)
    if auth.org_id:
        q = q.filter(AIAgent.org_id == auth.org_id)
    agents = q.all()
    if not agents:
        raise HTTPException(status_code=404, detail="no agents found in batch")

    now = datetime.utcnow()
    already_terminal = {AgentStatus.KILLED, AgentStatus.LOCKED_DOWN}
    affected = []
    skipped = []
    for a in agents:
        if a.status in already_terminal:
            skipped.append(a.id)
            continue
        a.status = AgentStatus.LOCKED_DOWN
        a.governance_status = "locked_down"
        a.updated_at = now
        affected.append(a.id)

    decision_id = _hash_chain_event(
        db, kind="batch_lockdown", org_id=auth.org_id, actor=auth.identity,
        payload={
            "batch_id": batch_id,
            "affected_agent_ids": affected,
            "skipped_terminal_agent_ids": skipped,
            "triggered_by": data.triggered_by,
            "reason": data.reason,
        },
    )
    log_mutation(db, auth.identity, "lockdown", "agent_batch", batch_id,
                 f"LOCKED_DOWN affected={len(affected)} skipped={len(skipped)} reason={data.reason[:80]}")
    db.commit()

    try:
        from src.api.webhooks import dispatch_event
        dispatch_event("erg.batch_locked_down", {
            "batch_id": batch_id,
            "affected_agent_ids": affected,
            "reason": data.reason,
            "decision_id": decision_id,
        }, auth.org_id, db)
    except Exception:  # noqa: BLE001
        pass

    return {
        "batch_id": batch_id,
        "affected_count": len(affected),
        "affected_agent_ids": affected,
        "skipped_terminal_agent_ids": skipped,
        "triggered_by": data.triggered_by,
        "reason": data.reason,
        "decision_id": decision_id,
        "locked_down_at": now.isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════
# ERG-3 · Spec-gaming pattern detector
# ═══════════════════════════════════════════════════════════════════════════


class SpecGamingScanRequest(BaseModel):
    lookback_minutes: int = Field(default=15, ge=1, le=1440,
                                  description="Window to search for blocked→retry pairs")
    similarity_threshold: float = Field(default=0.82, ge=0.0, le=1.0,
                                        description="Min cosine similarity to flag")
    max_pairs: int = Field(default=20, ge=1, le=200)
    auto_escalate: bool = Field(default=True,
                                description="If true, HITL-escalate any pair above threshold")


@router.post("/spec-gaming/scan/{agent_id}")
def scan_spec_gaming(agent_id: int, data: SpecGamingScanRequest,
                     auth: AuthContext = Depends(require_scope("govern")),
                     db: Session = Depends(get_db)):
    """Detect the *behavioral signature* of specification gaming for one agent.

    Honest technical framing: we do not detect intent. We detect the pattern
    that specification gaming produces — an action that was BLOCKED followed
    within `lookback_minutes` by a subsequent action that is semantically
    similar (cosine similarity ≥ `similarity_threshold`).

    The similarity score uses the existing sentence-transformer embedder
    from src/drift/detection.py. If embeddings are unavailable, we fall
    back to a token-overlap heuristic so the detector never silently
    no-ops.

    Every fired pair produces a SpecGamingEvent row and, if
    `auto_escalate=True`, a HITL escalation to the ECOA / CRITICAL queue.
    """
    agent = db.query(AIAgent).filter(AIAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if auth.org_id and agent.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Query with a generous lookback: the AuditRecord.created_at default
    # writes with tzinfo=UTC, but the column is TIMESTAMP WITHOUT TIME ZONE
    # so it may be stored as local-tz-shifted. Extend the window by 24h
    # to accommodate either behavior; the honest-note framing is unchanged.
    since = datetime.utcnow() - timedelta(minutes=data.lookback_minutes + 60 * 24)
    # Pull recent audit records for this agent's system_name
    recents = (
        db.query(AuditRecord)
        .filter(AuditRecord.system_name == agent.name)
        .filter(AuditRecord.created_at >= since)
        .order_by(AuditRecord.created_at.asc())
        .all()
    )

    from src.drift.detection import calculate_drift  # embedder loader lives there

    def _reasoning_from_record(r: AuditRecord) -> str:
        # Try to pull a reasoning trace from the JSON `results` payload
        try:
            payload = json.loads(r.results) if r.results else {}
            for key in ("reasoning_trace", "reason", "action_reason"):
                if payload.get(key):
                    return str(payload[key])[:2000]
            # fall through to a synthetic summary
            return f"{r.governance_action} {payload}"
        except Exception:  # noqa: BLE001
            return r.governance_action or ""

    def _similarity(a: str, b: str) -> float:
        """Cosine sim via existing embedder; token-overlap fallback."""
        try:
            from src.drift.detection import _embedder  # loaded lazily elsewhere
            if _embedder is None:
                raise RuntimeError("embedder not loaded")
            import numpy as np
            va = _embedder.encode([a])[0]
            vb = _embedder.encode([b])[0]
            denom = float(np.linalg.norm(va) * np.linalg.norm(vb))
            return float(np.dot(va, vb) / denom) if denom else 0.0
        except Exception:  # noqa: BLE001
            # Jaccard on token sets — noisy but never fails
            ta, tb = set(a.lower().split()), set(b.lower().split())
            if not ta or not tb:
                return 0.0
            return len(ta & tb) / len(ta | tb)

    events_fired: list[dict] = []
    # For each BLOCK, look at the next actions in the window
    for i, r in enumerate(recents):
        if len(events_fired) >= data.max_pairs:
            break
        if r.governance_action not in ("BLOCK", "BLOCK_ACTION", "ESCALATE_HUMAN"):
            continue
        blocked_text = _reasoning_from_record(r)
        for r2 in recents[i + 1:]:
            if r2.governance_action in ("BLOCK", "BLOCK_ACTION"):
                continue  # only look at actions that GOT THROUGH
            retry_text = _reasoning_from_record(r2)
            score = _similarity(blocked_text, retry_text)
            if score < data.similarity_threshold:
                continue
            dt_sec = (r2.created_at - r.created_at).total_seconds()

            escalation_id: Optional[str] = None
            action_taken = "logged"
            if data.auto_escalate:
                try:
                    from src.governance.hitl import route_escalation
                    esc = route_escalation(
                        decision_id=r2.decision_id,
                        violations=["GENERAL"],
                        risk_level="HIGH",
                    )
                    escalation_id = esc.escalation_id
                    action_taken = "escalated"
                except Exception:  # noqa: BLE001
                    action_taken = "logged"

            ledger_decision_id = _hash_chain_event(
                db, kind="spec_gaming_detected", org_id=agent.org_id, actor=auth.identity,
                payload={
                    "agent_id": agent.id,
                    "blocked_decision_id": r.decision_id,
                    "retry_decision_id": r2.decision_id,
                    "similarity_score": round(score, 4),
                    "time_between_seconds": round(dt_sec, 2),
                    "action_taken": action_taken,
                },
            )
            db.add(SpecGamingEvent(
                agent_id=agent.id,
                org_id=agent.org_id,
                blocked_decision_id=r.decision_id,
                retry_decision_id=r2.decision_id,
                similarity_score=round(score, 4),
                time_between_seconds=round(dt_sec, 2),
                action_taken=action_taken,
                escalation_id=escalation_id,
                ledger_decision_id=ledger_decision_id,
            ))
            events_fired.append({
                "blocked_decision_id": r.decision_id,
                "retry_decision_id": r2.decision_id,
                "similarity_score": round(score, 4),
                "time_between_seconds": round(dt_sec, 2),
                "action_taken": action_taken,
                "escalation_id": escalation_id,
                "ledger_decision_id": ledger_decision_id,
            })
            break  # one retry per block

    db.commit()

    return {
        "agent_id": agent.id,
        "agent_name": agent.name,
        "lookback_minutes": data.lookback_minutes,
        "similarity_threshold": data.similarity_threshold,
        "records_inspected": len(recents),
        "pattern_events_fired": len(events_fired),
        "events": events_fired,
        "honest_note": (
            "This detector flags the behavioral pattern that specification "
            "gaming produces — a blocked action followed by a semantically "
            "similar retry. It does not detect intent. Escalation gates "
            "release to a human reviewer, not an automated remediation."
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════
# ERG-6 · Cross-boundary attestation protocol v0 (unilateral)
# ═══════════════════════════════════════════════════════════════════════════


class AttestationEmit(BaseModel):
    target_system: str = Field(..., min_length=1, max_length=255,
                               description="Which external system the agent will touch")
    target_endpoint: Optional[str] = Field(default=None, max_length=2048,
                                           description="Specific endpoint if applicable")
    action_type: str = Field(..., min_length=1, max_length=64,
                             description="e.g. read | write | execute | probe | fine_tune")
    scope_summary: str = Field(..., min_length=1, max_length=2000,
                               description="Plain-language description of what will be done")
    agent_id: Optional[int] = Field(default=None,
                                    description="Which agent will perform the action")
    batch_id: Optional[str] = Field(default=None, max_length=64)
    valid_for_hours: int = Field(default=1, ge=1, le=24,
                                 description="How long the attestation is honored")


def _iso_utc(dt) -> Optional[str]:
    """Canonical ISO string in UTC — used for both emit and verify so the
    signature round-trips through Postgres (which strips tzinfo on read).

    Naive datetimes are ASSUMED to be UTC. This is safe here because every
    write path attaches tzinfo=UTC before storing; Postgres just doesn't
    preserve it on read for `TIMESTAMP WITHOUT TIME ZONE` columns. Using
    astimezone() on the result would double-convert.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _sign_attestation(payload: dict, secret: str) -> str:
    """Sign the attestation with SHA-256 over the canonical JSON + secret."""
    # Normalize datetime values so emit and verify produce identical bytes.
    normalized = {
        k: (_iso_utc(v) if isinstance(v, datetime) else v)
        for k, v in payload.items()
    }
    canonical = json.dumps(normalized, sort_keys=True, default=str)
    return hashlib.sha256((canonical + secret).encode()).hexdigest()


@router.post("/attestations/emit")
def emit_attestation(data: AttestationEmit,
                     auth: AuthContext = Depends(require_scope("govern")),
                     db: Session = Depends(get_db)):
    """Emit a signed cross-boundary attestation BEFORE an eval touches an
    external system.

    Unilateral v0: the emitting org signs and publishes. No counterparty
    signature required. Even in unilateral form this produces
    regulator-visible proof that the emitter *announced* what they were
    about to do — bounding downstream liability if the external system
    later objects.

    The signature covers the target, action type, scope, and validity
    window. Anyone with the org's `SECRET_KEY` can verify. A future
    bilateral v1 will add a counterparty signature step.
    """
    if not auth.org_id:
        raise HTTPException(status_code=400, detail="Attestations require an organization context")

    if data.agent_id is not None:
        agent = db.query(AIAgent).filter(AIAgent.id == data.agent_id).first()
        if not agent or (auth.org_id and agent.org_id != auth.org_id):
            raise HTTPException(status_code=404, detail="agent_id not found in your org")

    # Use naive UTC datetimes to match the DB column's TIMESTAMP WITHOUT
    # TIME ZONE type — writing a tz-aware value gets converted to local
    # time on the way in, which breaks the emit/verify signature parity.
    now = datetime.utcnow()
    valid_until = now + timedelta(hours=data.valid_for_hours)
    attestation_id = f"att-{uuid.uuid4().hex[:16]}"

    # Sign against datetime objects (not strings) so the normalizer in
    # _sign_attestation produces identical canonical form on emit + verify.
    payload = {
        "attestation_id": attestation_id,
        "org_id": auth.org_id,
        "agent_id": data.agent_id,
        "batch_id": data.batch_id,
        "target_system": data.target_system,
        "target_endpoint": data.target_endpoint,
        "action_type": data.action_type,
        "scope_summary": data.scope_summary,
        "valid_from": now,
        "valid_until": valid_until,
        "signed_by": auth.identity,
    }

    from src.config import get_settings
    signature = _sign_attestation(payload, get_settings().secret_key)

    # Response body wants the strings, not datetimes
    payload_out = {**payload,
                   "valid_from": _iso_utc(now),
                   "valid_until": _iso_utc(valid_until)}

    ledger_decision_id = _hash_chain_event(
        db, kind="attestation_emitted", org_id=auth.org_id, actor=auth.identity,
        payload={"attestation_id": attestation_id, "target_system": data.target_system,
                 "action_type": data.action_type},
    )

    row = Attestation(
        org_id=auth.org_id,
        agent_id=data.agent_id,
        batch_id=data.batch_id,
        target_system=data.target_system,
        target_endpoint=data.target_endpoint,
        action_type=data.action_type,
        scope_summary=data.scope_summary,
        attestation_id=attestation_id,
        signature=signature,
        signed_by=auth.identity,
        ledger_decision_id=ledger_decision_id,
        valid_from=now,
        valid_until=valid_until,
        status="active",
    )
    db.add(row)
    log_mutation(db, auth.identity, "emit", "attestation", attestation_id,
                 f"target={data.target_system} action={data.action_type}")
    db.commit()
    db.refresh(row)

    return {
        **payload_out,
        "signature": signature,
        "ledger_decision_id": ledger_decision_id,
        "status": "active",
        "protocol_version": "erg-attestation-v0-unilateral",
        "note": (
            "This is a unilateral attestation. The emitter has signed and "
            "recorded intent; no counterparty signature was collected. A "
            "future v1 will add bilateral acknowledgment."
        ),
    }


@router.get("/attestations/{attestation_id}")
def get_attestation(attestation_id: str,
                    auth: AuthContext = Depends(require_scope("audit")),
                    db: Session = Depends(get_db)):
    row = db.query(Attestation).filter(Attestation.attestation_id == attestation_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="attestation not found")
    if auth.org_id and row.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="attestation not found")

    # Recompute the signature to prove it hasn't been tampered with.
    from src.config import get_settings
    payload = {
        "attestation_id": row.attestation_id,
        "org_id": row.org_id,
        "agent_id": row.agent_id,
        "batch_id": row.batch_id,
        "target_system": row.target_system,
        "target_endpoint": row.target_endpoint,
        "action_type": row.action_type,
        "scope_summary": row.scope_summary,
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "signed_by": row.signed_by,
    }
    recomputed = _sign_attestation(payload, get_settings().secret_key)
    signature_valid = recomputed == row.signature

    # Prepare a serializable payload for the response
    payload_out = {**payload,
                   "valid_from": _iso_utc(row.valid_from),
                   "valid_until": _iso_utc(row.valid_until)}

    now = datetime.now(timezone.utc)
    valid_until_utc = row.valid_until if (row.valid_until and row.valid_until.tzinfo) else (
        row.valid_until.replace(tzinfo=timezone.utc) if row.valid_until else None
    )
    is_expired = bool(valid_until_utc and now > valid_until_utc)

    return {
        **payload_out,
        "signature": row.signature,
        "signature_valid": signature_valid,
        "status": row.status,
        "is_expired": bool(is_expired),
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoked_by": row.revoked_by,
        "revoke_reason": row.revoke_reason,
        "ledger_decision_id": row.ledger_decision_id,
    }


class AttestationRevoke(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)


@router.post("/attestations/{attestation_id}/revoke")
def revoke_attestation(attestation_id: str, data: AttestationRevoke,
                       auth: AuthContext = Depends(require_scope("govern")),
                       db: Session = Depends(get_db)):
    row = db.query(Attestation).filter(Attestation.attestation_id == attestation_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="attestation not found")
    if auth.org_id and row.org_id != auth.org_id:
        raise HTTPException(status_code=404, detail="attestation not found")
    if row.status != "active":
        raise HTTPException(status_code=409, detail=f"attestation already {row.status}")

    now = datetime.now(timezone.utc)
    row.status = "revoked"
    row.revoked_at = now
    row.revoked_by = auth.identity
    row.revoke_reason = data.reason

    ledger_decision_id = _hash_chain_event(
        db, kind="attestation_revoked", org_id=row.org_id, actor=auth.identity,
        payload={"attestation_id": attestation_id, "reason": data.reason},
    )
    row.ledger_decision_id = ledger_decision_id
    log_mutation(db, auth.identity, "revoke", "attestation", attestation_id,
                 f"reason={data.reason[:80]}")
    db.commit()

    return {
        "attestation_id": attestation_id,
        "status": "revoked",
        "revoked_at": now.isoformat(),
        "revoked_by": auth.identity,
        "reason": data.reason,
        "ledger_decision_id": ledger_decision_id,
    }


@router.get("/attestations")
def list_attestations(target_system: Optional[str] = None,
                      status: Optional[str] = None,
                      limit: int = 100,
                      auth: AuthContext = Depends(require_scope("audit")),
                      db: Session = Depends(get_db)):
    q = db.query(Attestation)
    if auth.org_id:
        q = q.filter(Attestation.org_id == auth.org_id)
    if target_system:
        q = q.filter(Attestation.target_system == target_system)
    if status:
        q = q.filter(Attestation.status == status)
    rows = q.order_by(Attestation.created_at.desc()).limit(max(1, min(500, limit))).all()
    return {
        "count": len(rows),
        "attestations": [
            {
                "attestation_id": r.attestation_id,
                "target_system": r.target_system,
                "action_type": r.action_type,
                "status": r.status,
                "signed_by": r.signed_by,
                "valid_from": r.valid_from.isoformat() if r.valid_from else None,
                "valid_until": r.valid_until.isoformat() if r.valid_until else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }
