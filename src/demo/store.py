"""Per-session isolated state store for the public /demo/* endpoints.

The demo endpoints are unauthenticated and run against production data-plane
functions (real hash-chain, real reason-code generator, real HITL router).
To keep them safe:

  * All state is per-session and lives in memory, never touching the SQL
    audit ledger, HITL store, or any customer data.
  * Sessions expire 1 hour after last activity.
  * The whole /demo/* namespace is rate-limited per client IP (30 req/min
    sliding window).
  * There is a hard cap on the number of concurrent sessions and records
    per session so a curious visitor can't grow the process memory.

Nothing in this module is imported by production endpoints, and no
production module imports the session store.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------------


DEMO_GENESIS_HASH = hashlib.sha256(b"GOVERNLAYER_DEMO_GENESIS").hexdigest()

MAX_SESSIONS = 500
MAX_RECORDS_PER_SESSION = 25
SESSION_TTL_SECONDS = 3600
RATE_LIMIT_PER_MINUTE = 30


@dataclass
class DemoLedgerEntry:
    """A single hash-chained entry in a demo session's isolated ledger."""
    id: int
    decision_id: str
    scenario: str
    system_name: str
    governance_action: str
    risk_score: float
    risk_level: str
    payload: dict
    previous_hash: str
    current_hash: str
    created_at: str


@dataclass
class DemoEscalation:
    """A HITL escalation created inside a demo session."""
    escalation_id: str
    decision_id: str
    violation_type: str
    risk_level: str
    assigned_reviewer: str
    sla_deadline: str
    created_at: str


@dataclass
class DemoSession:
    """Everything a single demo visitor accumulates during their tour."""
    session_id: str
    created_at: float
    last_seen: float
    ledger: list[DemoLedgerEntry] = field(default_factory=list)
    escalations: dict[str, DemoEscalation] = field(default_factory=dict)

    def last_hash(self) -> str:
        return self.ledger[-1].current_hash if self.ledger else DEMO_GENESIS_HASH


# ---------------------------------------------------------------------------
# In-memory registry
# ---------------------------------------------------------------------------


_sessions: dict[str, DemoSession] = {}
_sessions_lock = threading.Lock()


def _now() -> float:
    return time.time()


def _prune_expired_locked() -> None:
    now = _now()
    stale = [sid for sid, s in _sessions.items() if now - s.last_seen > SESSION_TTL_SECONDS]
    for sid in stale:
        _sessions.pop(sid, None)


def get_or_create_session(session_id: Optional[str]) -> DemoSession:
    """Return an existing session or create a new one.

    If a session_id is supplied and matches an existing (non-expired) session,
    that session is returned with `last_seen` refreshed. Otherwise a new
    session with a fresh id is created and returned.
    """
    with _sessions_lock:
        _prune_expired_locked()

        if session_id and session_id in _sessions:
            s = _sessions[session_id]
            s.last_seen = _now()
            return s

        if len(_sessions) >= MAX_SESSIONS:
            # Evict oldest to make room — public endpoint must never OOM
            oldest = min(_sessions.values(), key=lambda s: s.last_seen)
            _sessions.pop(oldest.session_id, None)

        new_id = session_id or f"demo-{uuid.uuid4().hex}"
        now = _now()
        s = DemoSession(session_id=new_id, created_at=now, last_seen=now)
        _sessions[new_id] = s
        return s


def get_session(session_id: str) -> Optional[DemoSession]:
    with _sessions_lock:
        _prune_expired_locked()
        s = _sessions.get(session_id)
        if s is not None:
            s.last_seen = _now()
        return s


def reset_session(session_id: str) -> DemoSession:
    """Clear all ledger + escalation state for a session, keep the id."""
    with _sessions_lock:
        now = _now()
        s = DemoSession(session_id=session_id, created_at=now, last_seen=now)
        _sessions[session_id] = s
        return s


def append_ledger(session: DemoSession, *, scenario: str, system_name: str,
                  governance_action: str, risk_score: float, risk_level: str,
                  payload: dict) -> DemoLedgerEntry:
    """Append a hash-chained entry to the session's isolated ledger."""
    with _sessions_lock:
        if len(session.ledger) >= MAX_RECORDS_PER_SESSION:
            # Silently drop oldest to keep the demo bounded
            session.ledger.pop(0)

        prev_hash = session.last_hash()
        decision_id = f"demo-{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).isoformat()

        record_data = {
            "decision_id": decision_id,
            "scenario": scenario,
            "system_name": system_name,
            "governance_action": governance_action,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "payload": payload,
            "created_at": created_at,
        }
        current_hash = hashlib.sha256(
            json.dumps({**record_data, "previous_hash": prev_hash},
                       sort_keys=True, default=str).encode()
        ).hexdigest()

        entry = DemoLedgerEntry(
            id=len(session.ledger) + 1,
            decision_id=decision_id,
            scenario=scenario,
            system_name=system_name,
            governance_action=governance_action,
            risk_score=risk_score,
            risk_level=risk_level,
            payload=payload,
            previous_hash=prev_hash,
            current_hash=current_hash,
            created_at=created_at,
        )
        session.ledger.append(entry)
        return entry


def add_escalation(session: DemoSession, esc: DemoEscalation) -> None:
    with _sessions_lock:
        session.escalations[esc.escalation_id] = esc


def verify_chain(session: DemoSession) -> dict:
    """Walk the session's chain and return an examiner-style verdict."""
    started = time.perf_counter()
    if not session.ledger:
        return {
            "status": "VERIFIED",
            "records_validated": 0,
            "chain_intact": True,
            "genesis_valid": True,
            "verification_time_ms": round((time.perf_counter() - started) * 1000, 2),
            "message": "Empty chain (genesis only). No records to verify yet.",
        }

    prev = DEMO_GENESIS_HASH
    for entry in session.ledger:
        if entry.previous_hash != prev:
            return {
                "status": "TAMPERED",
                "records_validated": entry.id - 1,
                "chain_intact": False,
                "genesis_valid": True,
                "verification_time_ms": round((time.perf_counter() - started) * 1000, 2),
                "message": f"Chain break at record {entry.id}: previous_hash mismatch.",
            }

        expected = hashlib.sha256(
            json.dumps({
                "decision_id": entry.decision_id,
                "scenario": entry.scenario,
                "system_name": entry.system_name,
                "governance_action": entry.governance_action,
                "risk_score": entry.risk_score,
                "risk_level": entry.risk_level,
                "payload": entry.payload,
                "created_at": entry.created_at,
                "previous_hash": entry.previous_hash,
            }, sort_keys=True, default=str).encode()
        ).hexdigest()
        if expected != entry.current_hash:
            return {
                "status": "TAMPERED",
                "records_validated": entry.id - 1,
                "chain_intact": False,
                "genesis_valid": True,
                "verification_time_ms": round((time.perf_counter() - started) * 1000, 2),
                "message": f"Hash mismatch at record {entry.id}.",
            }
        prev = entry.current_hash

    return {
        "status": "VERIFIED",
        "records_validated": len(session.ledger),
        "chain_intact": True,
        "genesis_valid": True,
        "first_record": session.ledger[0].decision_id,
        "last_record": session.ledger[-1].decision_id,
        "verification_time_ms": round((time.perf_counter() - started) * 1000, 2),
        "message": (
            "All records validated. Hash-chain integrity confirmed from "
            "GOVERNLAYER_DEMO_GENESIS to the latest entry."
        ),
    }


# ---------------------------------------------------------------------------
# Rate limiting — sliding window per client IP
# ---------------------------------------------------------------------------


_rate_hits: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def rate_limit_check(client_ip: str) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds).

    Uses a 60-second sliding window keyed by IP. Rejects after
    RATE_LIMIT_PER_MINUTE hits inside the window.
    """
    now = _now()
    window = 60.0

    with _rate_lock:
        bucket = _rate_hits.setdefault(client_ip, [])
        # Drop hits older than the window
        while bucket and now - bucket[0] > window:
            bucket.pop(0)

        if len(bucket) >= RATE_LIMIT_PER_MINUTE:
            retry_after = int(window - (now - bucket[0])) + 1
            return False, max(1, retry_after)

        bucket.append(now)
        return True, 0


# ---------------------------------------------------------------------------
# Test helpers — only used by tests
# ---------------------------------------------------------------------------


def _reset_all_state_for_testing() -> None:
    """Drop every session and rate-limit bucket. Do not call from production."""
    with _sessions_lock:
        _sessions.clear()
    with _rate_lock:
        _rate_hits.clear()
