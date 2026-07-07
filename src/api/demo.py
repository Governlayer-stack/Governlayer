"""Public, unauthenticated /demo/* endpoints.

Purpose: give prospects (investors, banking / healthcare / GRC buyers) a URL
they can visit and watch the GovernLayer decision pipeline execute on canned
data, without signing up.

Safety:
    * All state is per-session and per-visitor (in-memory session store).
    * Nothing here writes to the production audit ledger, HITL store, or
      any customer data.
    * The whole namespace is rate-limited per client IP (30 req/min).
    * Sessions expire 1 hour after last activity.

The demo IS truthful: it uses production functions where they exist
(reason-code generator, hash algorithm, HITL routing rules), so what a
prospect sees is what a customer will see — just against isolated data.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from src.demo import scenarios as demo_scenarios
from src.demo.store import (
    DemoLedgerEntry,
    DemoSession,
    get_or_create_session,
    get_session,
    rate_limit_check,
    reset_session,
    verify_chain,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/demo", tags=["demo"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(request: Request) -> None:
    ip = _client_ip(request)
    allowed, retry_after = rate_limit_check(ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": (
                    "Demo endpoints are rate-limited to keep them fast for "
                    "everyone. Try again in a moment."
                ),
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )


def _entry_to_dict(entry: DemoLedgerEntry) -> dict:
    return asdict(entry)


def _session_snapshot(session: DemoSession) -> dict:
    return {
        "session_id": session.session_id,
        "created_at_epoch": session.created_at,
        "last_seen_epoch": session.last_seen,
        "ledger_count": len(session.ledger),
        "ledger": [_entry_to_dict(e) for e in session.ledger],
        "escalations": [asdict(e) for e in session.escalations.values()],
    }


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ScenarioInfo(BaseModel):
    name: str
    title: str
    buyer: str
    trigger: str
    regulator: str


class ScenarioListResponse(BaseModel):
    count: int
    scenarios: list[ScenarioInfo]
    session_id: Optional[str] = Field(
        default=None,
        description="Pass this back on subsequent /demo/* calls to accumulate a chain.",
    )


class RunResponse(BaseModel):
    session_id: str
    result: dict
    ledger_length: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/scenarios", response_model=ScenarioListResponse)
def list_scenarios(
    request: Request,
    x_demo_session: Optional[str] = Header(default=None),
):
    """List the demo scenarios a visitor can run.

    Optionally passes back the visitor's session id (creates one if the
    `X-Demo-Session` header is absent), so subsequent runs can accumulate
    a shared hash-chain that the visitor can verify at the end.
    """
    _enforce_rate_limit(request)
    session = get_or_create_session(x_demo_session)
    return ScenarioListResponse(
        count=len(demo_scenarios.SCENARIOS),
        scenarios=[
            ScenarioInfo(**{
                "name": s.name, "title": s.title, "buyer": s.buyer,
                "trigger": s.trigger, "regulator": s.regulator,
            })
            for s in demo_scenarios.SCENARIOS.values()
        ],
        session_id=session.session_id,
    )


@router.post("/scenarios/{name}/run", response_model=RunResponse)
def run_scenario(
    name: str,
    request: Request,
    x_demo_session: Optional[str] = Header(default=None),
):
    """Run a scenario (banking | cyber | healthcare).

    Appends the resulting decision to the visitor's session-scoped ledger
    and returns the full decision payload, including the escalation record
    if one was created and the hash-chain pointers so a visitor can watch
    the chain grow.
    """
    _enforce_rate_limit(request)
    if name not in demo_scenarios.SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{name}'. Valid: {sorted(demo_scenarios.SCENARIOS)}",
        )

    session = get_or_create_session(x_demo_session)
    try:
        result = demo_scenarios.run(name, session)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return RunResponse(
        session_id=session.session_id,
        result=result,
        ledger_length=len(session.ledger),
    )


@router.get("/state/{session_id}")
def get_state(session_id: str, request: Request):
    """Return the full accumulated state for a session.

    Includes ledger and any HITL escalations. Used by a demo frontend to
    render the "as the visitor clicks through, this is what has piled up
    in the ledger" panel.
    """
    _enforce_rate_limit(request)
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired.")
    return _session_snapshot(session)


@router.post("/reset/{session_id}")
def reset(session_id: str, request: Request):
    """Wipe the session's ledger and escalations back to the empty state."""
    _enforce_rate_limit(request)
    session = reset_session(session_id)
    return {
        "session_id": session.session_id,
        "message": "Session reset. Ledger empty, chain returned to genesis.",
    }


@router.get("/ledger/verify/{session_id}")
def verify(session_id: str, request: Request):
    """Verify the session's hash-chain is intact.

    This is the closing "one API call, mathematical proof" moment of the
    demo. Returns records_validated, chain_intact, verification_time_ms,
    and the first/last record identifiers.
    """
    _enforce_rate_limit(request)
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired.")
    return verify_chain(session)
