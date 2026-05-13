import json
import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.config import get_settings
from src.drift.detection import analyze_reasoning
from src.models.database import AuditRecord, compute_hash, get_db, get_last_hash, log_mutation
from src.models.schemas import GovernRequest
from src.security.auth import verify_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["governance"])
settings = get_settings()


def _run_framework_evaluation(use_case: str, reasoning_trace: str) -> list[dict]:
    """Evaluate all loaded frameworks against the use case + reasoning trace.

    Returns a list of dicts shaped for the API response. On any failure,
    logs a warning and returns an empty list — framework evaluation must
    NEVER break the core governance pipeline.
    """
    try:
        from src.frameworks.registry import evaluate_use_case, get_framework

        results = evaluate_use_case(use_case or "", reasoning_trace or "")
        out: list[dict] = []
        for r in results:
            framework_id = r.rule_id.split(".")[0] if "." in r.rule_id else ""
            fw = get_framework(framework_id) if framework_id else None
            rule = fw.get_rule(r.rule_id) if fw else None
            out.append({
                "rule_id": r.rule_id,
                "framework": framework_id,
                "passed": r.passed,
                "severity": r.severity,
                "finding": r.finding,
                "citations": list(rule.citations) if rule else [],
                "evidence": r.evidence,
            })
        return out
    except Exception as e:  # noqa: BLE001 — never break governance for framework bugs
        logger.warning("Framework evaluation failed; falling through. err=%s", e)
        return []


def _apply_framework_overrides(
    action: str, reason: str, framework_results: list[dict]
) -> tuple[str, str]:
    """Apply framework rule failures to the existing governance action.

    Rules:
    - CRITICAL failure: force BLOCK regardless of current action.
    - HIGH failure: if currently APPROVE, downgrade to ESCALATE_HUMAN.
      Otherwise, append finding to reason but keep action.
    """
    failed = [r for r in framework_results if not r.get("passed")]
    if not failed:
        return action, reason

    critical = [r for r in failed if r.get("severity") == "CRITICAL"]
    high = [r for r in failed if r.get("severity") == "HIGH"]

    def _fmt(r: dict) -> str:
        return f"{r['rule_id']} ({r.get('finding', '').strip() or 'rule failed'})"

    if critical:
        finding_str = "; ".join(_fmt(r) for r in critical)
        new_reason = f"BLOCKED: framework rule failed: {finding_str}"
        if action != "BLOCK":
            return "BLOCK", new_reason
        return "BLOCK", f"{reason} | framework rule failed: {finding_str}"

    if high:
        finding_str = "; ".join(_fmt(r) for r in high)
        if action == "APPROVE":
            return "ESCALATE_HUMAN", f"ESCALATED: framework rule failed: {finding_str}"
        return action, f"{reason} | framework rule failed: {finding_str}"

    return action, reason


def compute_risk_scores(request: GovernRequest) -> dict:
    return {
        "Privacy": 100 if not request.handles_personal_data else 40,
        "Autonomy_Risk": 100 if not request.makes_autonomous_decisions else 30,
        "Infrastructure_Risk": 100 if not request.used_in_critical_infrastructure else 25,
        "Oversight": 100 if request.has_human_oversight else 20,
        "Transparency": 100 if request.is_explainable else 30,
        "Fairness": 100 if request.has_bias_testing else 25,
    }


@router.post("/govern")
def govern_decision(request: GovernRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    drift_result = analyze_reasoning(reasoning_trace=request.reasoning_trace, use_case=request.use_case)
    scores = compute_risk_scores(request)
    overall_risk = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall_risk >= 80 else "MEDIUM" if overall_risk >= 50 else "HIGH"

    if drift_result["vetoed"]:
        governance_action = "BLOCK"
        dc = drift_result['drift_coefficient']
        reason = f"BLOCKED: Behavioral drift detected. D_c={dc} exceeds threshold. {drift_result['explanation']}"
    elif risk_level == "HIGH":
        governance_action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: High risk score {round(overall_risk)}/100. Requires human review."
    elif risk_level == "MEDIUM" and drift_result["semantic_risk_flags"] > 0:
        governance_action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: Medium risk with {drift_result['semantic_risk_flags']} semantic risk flags."
    else:
        governance_action = "APPROVE"
        dc = drift_result['drift_coefficient']
        reason = f"APPROVED: Risk score {round(overall_risk)}/100. Drift coefficient {dc} within safe boundaries."

    # Framework rules engine — runs after drift+risk+decision, before ledger write.
    framework_results = _run_framework_evaluation(request.use_case, request.reasoning_trace)
    governance_action, reason = _apply_framework_overrides(
        governance_action, reason, framework_results
    )

    decision_id = str(uuid.uuid4())
    previous_hash = get_last_hash(db)
    failed_rules = [r for r in framework_results if not r.get("passed")]
    record_data = {
        "decision_id": decision_id,
        "system_name": request.system_name,
        "governance_action": governance_action,
        "drift_coefficient": drift_result["drift_coefficient"],
        "risk_score": overall_risk,
        "policy_version": settings.policy_version,
        "framework_failed_rule_ids": [r["rule_id"] for r in failed_rules],
        "framework_failed_count": len(failed_rules),
        "created_at": datetime.utcnow().isoformat(),
    }
    current_hash = compute_hash({**record_data, "previous_hash": previous_hash})

    # No new migration this session — embed framework findings JSON inside the existing
    # `results` Text column so they're captured cryptographically by the ledger hash.
    results_payload = json.dumps({
        "reason": reason,
        "framework_findings": framework_results,
    })

    audit = AuditRecord(
        decision_id=decision_id, system_name=request.system_name, industry=request.use_case,
        audited_by=email, frameworks_audited="NIST_AI_RMF,EU_AI_ACT,ISO_42001",
        results=results_payload,
        risk_score=overall_risk, risk_level=risk_level, governance_action=governance_action,
        policy_version=settings.policy_version, previous_hash=previous_hash, current_hash=current_hash,
    )
    db.add(audit)
    log_mutation(db, email, "create", "governance_decision", decision_id,
                 f"{governance_action}: {request.system_name} risk={round(overall_risk)} "
                 f"framework_failures={len(failed_rules)}")
    db.commit()

    # Fire webhooks for governance events
    from src.api.webhooks import dispatch_event
    event_payload = {
        "decision_id": decision_id, "system": request.system_name,
        "action": governance_action, "risk_score": round(overall_risk),
        "risk_level": risk_level,
        "framework_failed_count": len(failed_rules),
    }
    dispatch_event(f"governance.{governance_action.lower()}", event_payload, None, db)

    return {
        "decision_id": decision_id, "system": request.system_name,
        "governance_action": governance_action, "reason": reason,
        "drift_analysis": drift_result, "risk_score": round(overall_risk),
        "risk_level": risk_level, "dimension_scores": scores,
        "current_hash": current_hash, "policy_version": settings.policy_version,
        "framework_results": framework_results,
        "timestamp": datetime.utcnow().isoformat(),
    }
