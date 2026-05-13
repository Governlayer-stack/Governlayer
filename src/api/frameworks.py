"""Framework Policy-Rules API.

Exposes the structured framework registry over HTTP. All endpoints sit
behind the existing JWT verify_token dependency to keep parity with the
other v1 routers.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.frameworks.registry import (
    evaluate_use_case,
    framework_summary,
    get_all_frameworks,
    get_framework,
    triggered_rules,
)
from src.security.auth import verify_token


router = APIRouter(prefix="/v1/frameworks", tags=["Frameworks"])


class EvaluateRequest(BaseModel):
    use_case: str = Field(
        ...,
        description="Short natural-language description of the AI use case under review.",
    )
    reasoning_trace: str = Field(
        default="",
        description=(
            "Optional reasoning trace / system behaviour log to scan alongside "
            "the use case. Often produced by the achonye orchestrator."
        ),
    )


@router.get("")
def list_frameworks(_: str = Depends(verify_token)):
    """List all loaded frameworks with metadata (id, name, jurisdiction, rule count)."""
    return {
        "count": len(get_all_frameworks()),
        "frameworks": framework_summary(),
    }


@router.get("/{framework_id}")
def get_framework_rules(framework_id: str, _: str = Depends(verify_token)):
    """Return the full rule list for a single framework."""
    fw = get_framework(framework_id)
    if fw is None:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")
    return fw.to_dict()


@router.post("/{framework_id}/evaluate")
def evaluate_framework(
    framework_id: str,
    body: EvaluateRequest,
    _: str = Depends(verify_token),
):
    """Evaluate a use case against a framework's rules.

    Returns triggered rules (matched by keyword) plus the RuleResults from
    every rule that has an evaluator wired in.
    """
    fw = get_framework(framework_id)
    if fw is None:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")

    triggered = triggered_rules(body.use_case, body.reasoning_trace, framework_id)
    results = evaluate_use_case(body.use_case, body.reasoning_trace, framework_id)

    failed = [r for r in results if not r.passed]
    return {
        "framework_id": fw.id,
        "framework_name": fw.name,
        "use_case": body.use_case,
        "triggered_rule_count": len(triggered),
        "evaluated_count": len(results),
        "failed_count": len(failed),
        "triggered_rules": [r.to_dict() for r in triggered],
        "results": [r.to_dict() for r in results],
        "summary": {
            "any_critical_failure": any(
                (not r.passed) and r.severity == "CRITICAL" for r in results
            ),
            "any_high_failure": any(
                (not r.passed) and r.severity == "HIGH" for r in results
            ),
        },
    }
