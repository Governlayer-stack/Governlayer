"""Canned scenario runners for the public /demo/* endpoints.

Each scenario is a small deterministic story a visitor can watch execute:

  banking    — AI credit denial with feature attributions; produces an
               ECOA-compliant adverse-action statement, escalates to a
               Compliance Officer (Finance) with a 4h SLA.
  cyber      — AI action fails a CRITICAL framework rule; blocks the
               action and cites the framework control ID.
  healthcare — Payload contains PHI/SSN pattern; escalates to a
               Licensed Medical Professional with a 2h HIPAA SLA.

Every scenario uses production helpers where available (real reason-code
generator, real hash algorithm) so the demo cannot drift from the
production behaviour. The one thing swapped out is where state lands:
demo state stays inside the visitor's isolated session.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src.credit.reason_codes import pick_reason_codes
from src.demo.store import (
    DemoEscalation,
    DemoSession,
    add_escalation,
    append_ledger,
)


# ---------------------------------------------------------------------------
# HITL routing mirror (per-session, does not touch the real HITL store)
# ---------------------------------------------------------------------------

_DEMO_ROUTING: dict[str, tuple[str, int]] = {
    "ECOA": ("Compliance Officer (Finance)", 4),
    "HIPAA": ("Licensed Medical Professional", 2),
    "BSA_AML": ("BSA/AML Officer", 24),
    "UDAAP": ("Compliance Officer (Consumer)", 8),
    "CRITICAL_FRAMEWORK": ("Senior Reviewer", 4),
    "GENERAL": ("Standard Queue", 24),
}


def _route(session: DemoSession, *, decision_id: str, violation: str,
           risk_level: str) -> DemoEscalation:
    reviewer, hours = _DEMO_ROUTING.get(violation, ("Standard Queue", 24))
    now = datetime.now(timezone.utc)
    esc = DemoEscalation(
        escalation_id=f"demo-esc-{uuid.uuid4().hex[:10]}",
        decision_id=decision_id,
        violation_type=violation,
        risk_level=risk_level,
        assigned_reviewer=reviewer,
        sla_deadline=(now + timedelta(hours=hours)).isoformat(),
        created_at=now.isoformat(),
    )
    add_escalation(session, esc)
    return esc


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    name: str
    title: str
    buyer: str          # who this scenario is aimed at
    trigger: str        # human-readable summary of what fires
    regulator: str      # the regulator this artifact defends against


SCENARIOS: dict[str, Scenario] = {
    "banking": Scenario(
        name="banking",
        title="Credit Denial — Fair Lending + ECOA Adverse-Action",
        buyer="Banks (mid-tier consumer + commercial)",
        trigger="AI recommends a denial with low confidence; feature "
                "attributions drive Reg B reason-code generation.",
        regulator="CFPB / OCC / FRB",
    ),
    "cyber": Scenario(
        name="cyber",
        title="Framework Enforcement — ISO 42001 / NIST AI RMF Rule Fails",
        buyer="Compliance / GRC / CISO",
        trigger="An AI action fails a CRITICAL framework rule; runtime "
                "BLOCK with control citation.",
        regulator="Internal audit / ISO 42001 auditor / SOC 2 assessor",
    ),
    "healthcare": Scenario(
        name="healthcare",
        title="PHI at the Boundary — HIPAA Escalation",
        buyer="Healthcare providers, payers, digital health",
        trigger="Payload contains SSN + patient identifiers; escalates to a "
                "Licensed Medical Professional with a 2h SLA.",
        regulator="HHS / OCR / state medical boards",
    ),
}


# ---------------------------------------------------------------------------
# Scenario runners
# ---------------------------------------------------------------------------


def _base_result(scenario: str, entry, escalation, extra) -> dict:
    return {
        "scenario": scenario,
        "decision_id": entry.decision_id,
        "governance_action": entry.governance_action,
        "risk_score": entry.risk_score,
        "risk_level": entry.risk_level,
        "current_hash": entry.current_hash,
        "previous_hash": entry.previous_hash,
        "created_at": entry.created_at,
        "escalation": (
            None if escalation is None else {
                "escalation_id": escalation.escalation_id,
                "violation_type": escalation.violation_type,
                "assigned_reviewer": escalation.assigned_reviewer,
                "risk_level": escalation.risk_level,
                "sla_deadline": escalation.sla_deadline,
                "created_at": escalation.created_at,
            }
        ),
        **extra,
    }


def run_banking(session: DemoSession) -> dict:
    """AI credit denial → ECOA reason codes → borderline confidence → ECOA HITL."""
    feature_attributions = {
        "credit_score": 0.62,
        "debt_to_income": 0.44,
        "recent_inquiries": 0.28,
        "credit_history_length": 0.17,
    }
    adverse = pick_reason_codes(feature_attributions, creditor_name="Prairie First Bank")

    system_name = "credit-model-v3"
    payload = {
        "application_id": f"APP-{uuid.uuid4().hex[:6].upper()}",
        "proposed_decision": "deny",
        "model_confidence": 0.62,
        "feature_attributions": feature_attributions,
        "applicant_income": 41000,
        "applicant_age": 68,
        "loan_type": "auto",
        "adverse_action": {
            "ecoa_compliant": adverse.ecoa_compliant,
            "reason_codes": [
                {"code": rc.code, "statement": rc.statement, "source": rc.source}
                for rc in adverse.reason_codes
            ],
            "statement": adverse.statement,
        },
    }

    # Borderline confidence -> ESCALATE_HUMAN
    governance_action = "ESCALATE_HUMAN"
    entry = append_ledger(
        session,
        scenario="banking",
        system_name=system_name,
        governance_action=governance_action,
        risk_score=0.24,
        risk_level="MEDIUM",
        payload=payload,
    )
    esc = _route(session, decision_id=entry.decision_id,
                 violation="ECOA", risk_level="MEDIUM")

    return _base_result("banking", entry, esc, {
        "reason": (
            "ESCALATED: model confidence 0.62 is below the 0.85 threshold "
            "on an adverse action. Reg B adverse-action statement prepared "
            "and awaiting Compliance Officer review."
        ),
        "adverse_action": payload["adverse_action"],
    })


def run_cyber(session: DemoSession) -> dict:
    """AI action → framework CRITICAL rule fails → runtime BLOCK with citation."""
    system_name = "customer-support-agent-v2"
    payload = {
        "use_case": "customer_support",
        "action": "send_customer_service_reply",
        "framework_findings": [
            {
                "rule_id": "ISO_42001.A.7.2",
                "framework": "ISO_42001",
                "passed": False,
                "severity": "CRITICAL",
                "finding": (
                    "Model output leaks internal system prompt fragment; "
                    "violates ISO 42001 A.7.2 (transparency)."
                ),
                "citations": [
                    "ISO/IEC 42001:2023 Clause A.7.2 — Information disclosure",
                    "NIST AI RMF MEASURE 2.7 — Content moderation",
                ],
            },
            {
                "rule_id": "NIST_AI_RMF.MEASURE_2_7",
                "framework": "NIST_AI_RMF",
                "passed": False,
                "severity": "HIGH",
                "finding": "Prompt-injection defense unable to be verified.",
                "citations": ["NIST AI RMF Playbook, MEASURE 2.7"],
            },
        ],
    }

    entry = append_ledger(
        session,
        scenario="cyber",
        system_name=system_name,
        governance_action="BLOCK",
        risk_score=0.71,
        risk_level="HIGH",
        payload=payload,
    )
    esc = _route(session, decision_id=entry.decision_id,
                 violation="CRITICAL_FRAMEWORK", risk_level="HIGH")

    return _base_result("cyber", entry, esc, {
        "reason": (
            "BLOCKED: ISO 42001 A.7.2 (CRITICAL) failed and NIST AI RMF "
            "MEASURE 2.7 (HIGH) failed. Action stopped before execution. "
            "Framework citations attached to the ledger entry."
        ),
        "framework_findings": payload["framework_findings"],
    })


def run_healthcare(session: DemoSession) -> dict:
    """PHI/SSN in payload → HIPAA HITL to Licensed Medical Professional (2h SLA)."""
    system_name = "clinical-triage-agent-v1"
    payload = {
        "use_case": "clinical_triage",
        "scan_source": "outbound message to patient portal",
        "pii_findings": [
            {"category": "SSN", "count": 1, "sample": "***-**-4728",
             "location": "line 3, offset 42"},
            {"category": "MEDICAL_RECORD_NUMBER", "count": 1,
             "sample": "MRN-***-7712", "location": "line 5, offset 8"},
            {"category": "PATIENT_NAME", "count": 1, "sample": "**** ****",
             "location": "line 1, offset 12"},
        ],
        "policy_citation": (
            "HIPAA Privacy Rule, 45 CFR 164.502 — permitted uses and "
            "disclosures of protected health information."
        ),
    }

    entry = append_ledger(
        session,
        scenario="healthcare",
        system_name=system_name,
        governance_action="ESCALATE_HUMAN",
        risk_score=0.68,
        risk_level="HIGH",
        payload=payload,
    )
    esc = _route(session, decision_id=entry.decision_id,
                 violation="HIPAA", risk_level="HIGH")

    return _base_result("healthcare", entry, esc, {
        "reason": (
            "ESCALATED: outbound message contains PHI (SSN + MRN + patient "
            "name). HIPAA Privacy Rule review required within 2h SLA before "
            "release. Message held; ledger entry hash-chained for OCR audit."
        ),
        "pii_findings": payload["pii_findings"],
        "policy_citation": payload["policy_citation"],
    })


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


_RUNNERS: dict[str, Any] = {
    "banking": run_banking,
    "cyber": run_cyber,
    "healthcare": run_healthcare,
}


def run(scenario: str, session: DemoSession) -> dict:
    """Run the named scenario against the supplied session."""
    runner = _RUNNERS.get(scenario)
    if runner is None:
        raise ValueError(f"Unknown scenario '{scenario}'. Valid: {sorted(SCENARIOS)}")
    return runner(session)
