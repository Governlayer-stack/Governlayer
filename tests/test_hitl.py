"""Tests for HITL SLA Deadline Engine.

Validates patent-compliant human-in-the-loop escalation:
    - Violation-based routing (ECOA, EEOC, HIPAA)
    - SLA deadline calculation
    - Escalation resolution with justification
    - CRITICAL decisions require justification
    - SLA breach detection
"""

import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from src.governance.hitl import (
    EscalationRequest,
    EscalationStatus,
    ViolationType,
    check_sla_compliance,
    escalation_to_dict,
    get_sla_dashboard,
    resolve_escalation,
    route_escalation,
    _escalations,
    _store_lock,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_escalations():
    """Clear the in-memory escalation store between tests."""
    with _store_lock:
        _escalations.clear()
    yield
    with _store_lock:
        _escalations.clear()


# ═══════════════════════════════════════════════════════════════════════════
# Violation-based routing
# ═══════════════════════════════════════════════════════════════════════════

class TestViolationRouting:
    """Test routing decisions based on violation type."""

    def test_ecoa_routes_to_compliance_officer(self):
        esc = route_escalation("decision-1", ["ECOA"], "HIGH")
        assert esc.assigned_reviewer == "Compliance Officer (Finance)"
        assert esc.violation_type == ViolationType.ECOA

    def test_eeoc_routes_to_hr_compliance(self):
        esc = route_escalation("decision-2", ["EEOC"], "MEDIUM")
        assert esc.assigned_reviewer == "HR Compliance Officer"
        assert esc.violation_type == ViolationType.EEOC

    def test_hipaa_routes_to_medical_professional(self):
        esc = route_escalation("decision-3", ["HIPAA"], "HIGH")
        assert esc.assigned_reviewer == "Licensed Medical Professional"
        assert esc.violation_type == ViolationType.HIPAA

    def test_general_high_risk_routes_to_senior_reviewer(self):
        esc = route_escalation("decision-4", ["GENERAL"], "HIGH")
        assert esc.assigned_reviewer == "Senior Reviewer"

    def test_general_medium_risk_routes_to_standard_queue(self):
        esc = route_escalation("decision-5", ["GENERAL"], "MEDIUM")
        assert esc.assigned_reviewer == "Standard Queue"

    def test_general_low_risk_routes_to_standard_queue(self):
        esc = route_escalation("decision-6", ["GENERAL"], "LOW")
        assert esc.assigned_reviewer == "Standard Queue"

    def test_unknown_violation_falls_to_risk_routing(self):
        esc = route_escalation("decision-7", ["UNKNOWN_TYPE"], "MEDIUM")
        assert esc.assigned_reviewer == "Standard Queue"

    def test_multiple_violations_most_restrictive_sla_wins(self):
        """HIPAA (2h) should win over ECOA (4h) when both present."""
        esc = route_escalation("decision-8", ["ECOA", "HIPAA"], "MEDIUM")
        now = datetime.now(timezone.utc)
        # HIPAA = 2h is the shortest
        time_to_deadline = (esc.sla_deadline - now).total_seconds()
        # Should be around 2 hours (7200s), not 4 hours
        assert time_to_deadline < 3 * 3600  # Less than 3h

    def test_critical_risk_can_shorten_violation_sla(self):
        """CRITICAL risk (4h) should override ECOA (4h) — stays at 4h minimum."""
        esc = route_escalation("decision-9", ["ECOA"], "CRITICAL")
        now = datetime.now(timezone.utc)
        time_to_deadline = (esc.sla_deadline - now).total_seconds()
        # CRITICAL = 4h, ECOA = 4h => min is 4h
        assert time_to_deadline <= 4 * 3600 + 10  # Approx 4h with tolerance


# ═══════════════════════════════════════════════════════════════════════════
# SLA Deadline Calculation
# ═══════════════════════════════════════════════════════════════════════════

class TestSLADeadlineCalculation:
    """Test that SLA deadlines are correctly computed."""

    def test_ecoa_4_hour_sla(self):
        esc = route_escalation("d1", ["ECOA"], "LOW")
        expected_hours = 4
        elapsed = (esc.sla_deadline - esc.created_at).total_seconds()
        assert abs(elapsed - expected_hours * 3600) < 5  # Within 5 seconds

    def test_eeoc_4_hour_sla(self):
        esc = route_escalation("d2", ["EEOC"], "LOW")
        elapsed = (esc.sla_deadline - esc.created_at).total_seconds()
        assert abs(elapsed - 4 * 3600) < 5

    def test_hipaa_2_hour_sla(self):
        esc = route_escalation("d3", ["HIPAA"], "LOW")
        elapsed = (esc.sla_deadline - esc.created_at).total_seconds()
        assert abs(elapsed - 2 * 3600) < 5

    def test_high_risk_general_8_hour_sla(self):
        esc = route_escalation("d4", ["GENERAL"], "HIGH")
        elapsed = (esc.sla_deadline - esc.created_at).total_seconds()
        assert abs(elapsed - 8 * 3600) < 5

    def test_medium_risk_general_24_hour_sla(self):
        esc = route_escalation("d5", ["GENERAL"], "MEDIUM")
        elapsed = (esc.sla_deadline - esc.created_at).total_seconds()
        assert abs(elapsed - 24 * 3600) < 5

    def test_low_risk_general_48_hour_sla(self):
        esc = route_escalation("d6", ["GENERAL"], "LOW")
        elapsed = (esc.sla_deadline - esc.created_at).total_seconds()
        assert abs(elapsed - 48 * 3600) < 5

    def test_sla_deadline_is_timezone_aware(self):
        esc = route_escalation("d7", ["ECOA"], "HIGH")
        assert esc.sla_deadline.tzinfo is not None
        assert esc.created_at.tzinfo is not None


# ═══════════════════════════════════════════════════════════════════════════
# SLA Compliance Checking
# ═══════════════════════════════════════════════════════════════════════════

class TestSLACompliance:
    """Test SLA compliance status checking."""

    def test_pending_escalation_is_compliant(self):
        esc = route_escalation("d1", ["ECOA"], "HIGH")
        result = check_sla_compliance(esc.escalation_id)
        assert result["sla_status"] == "compliant"
        assert result["remaining_seconds"] > 0

    def test_resolved_escalation_reports_correctly(self):
        esc = route_escalation("d2", ["ECOA"], "HIGH")
        resolve_escalation(esc.escalation_id, "reviewer-1", "approved", "Justified")
        result = check_sla_compliance(esc.escalation_id)
        assert result["sla_status"] == "resolved"
        assert result["sla_met"] is True

    def test_expired_escalation_reports_breached(self):
        """Manually set the SLA deadline in the past to simulate breach."""
        esc = route_escalation("d3", ["ECOA"], "HIGH")
        with _store_lock:
            esc.sla_deadline = datetime.now(timezone.utc) - timedelta(hours=1)
        result = check_sla_compliance(esc.escalation_id)
        assert result["sla_status"] == "breached"
        assert result["exceeded_by_seconds"] > 0

    def test_nonexistent_escalation_raises(self):
        with pytest.raises(ValueError, match="not found"):
            check_sla_compliance("nonexistent-id")


# ═══════════════════════════════════════════════════════════════════════════
# Escalation Resolution
# ═══════════════════════════════════════════════════════════════════════════

class TestEscalationResolution:
    """Test human reviewer resolution of escalations."""

    def test_approve_escalation(self):
        esc = route_escalation("d1", ["ECOA"], "HIGH")
        resolved = resolve_escalation(
            esc.escalation_id, "reviewer-1", "approved", "Risk accepted"
        )
        assert resolved.status == EscalationStatus.APPROVED
        assert resolved.resolved_by == "reviewer-1"
        assert resolved.justification == "Risk accepted"
        assert resolved.resolved_at is not None

    def test_reject_escalation(self):
        esc = route_escalation("d2", ["HIPAA"], "HIGH")
        resolved = resolve_escalation(
            esc.escalation_id, "reviewer-2", "rejected", "Non-compliant"
        )
        assert resolved.status == EscalationStatus.REJECTED

    def test_critical_requires_justification(self):
        esc = route_escalation("d3", ["ECOA"], "CRITICAL")
        with pytest.raises(ValueError, match="justification"):
            resolve_escalation(esc.escalation_id, "reviewer-1", "approved", "")

    def test_critical_with_justification_succeeds(self):
        esc = route_escalation("d4", ["ECOA"], "CRITICAL")
        resolved = resolve_escalation(
            esc.escalation_id, "reviewer-1", "approved",
            "Risk fully documented and mitigated per compliance review"
        )
        assert resolved.status == EscalationStatus.APPROVED

    def test_critical_whitespace_justification_rejected(self):
        esc = route_escalation("d5", ["HIPAA"], "CRITICAL")
        with pytest.raises(ValueError, match="justification"):
            resolve_escalation(esc.escalation_id, "reviewer-1", "approved", "   ")

    def test_invalid_decision_raises(self):
        esc = route_escalation("d6", ["ECOA"], "HIGH")
        with pytest.raises(ValueError, match="Invalid decision"):
            resolve_escalation(esc.escalation_id, "reviewer-1", "maybe")

    def test_double_resolution_raises(self):
        esc = route_escalation("d7", ["ECOA"], "MEDIUM")
        resolve_escalation(esc.escalation_id, "reviewer-1", "approved", "ok")
        with pytest.raises(ValueError, match="already resolved"):
            resolve_escalation(esc.escalation_id, "reviewer-2", "rejected", "no")

    def test_nonexistent_resolution_raises(self):
        with pytest.raises(ValueError, match="not found"):
            resolve_escalation("bad-id", "reviewer-1", "approved")


# ═══════════════════════════════════════════════════════════════════════════
# Dashboard & Serialization
# ═══════════════════════════════════════════════════════════════════════════

class TestDashboardAndSerialization:
    """Test the SLA dashboard and serialization utilities."""

    def test_dashboard_empty(self):
        dashboard = get_sla_dashboard()
        assert dashboard["total"] == 0
        assert dashboard["summary"]["pending_count"] == 0

    def test_dashboard_with_pending(self):
        route_escalation("d1", ["ECOA"], "HIGH")
        route_escalation("d2", ["HIPAA"], "MEDIUM")
        dashboard = get_sla_dashboard()
        assert dashboard["total"] == 2
        assert dashboard["summary"]["pending_count"] == 2

    def test_dashboard_with_resolved(self):
        esc = route_escalation("d1", ["ECOA"], "MEDIUM")
        resolve_escalation(esc.escalation_id, "rev-1", "approved", "ok")
        dashboard = get_sla_dashboard()
        assert dashboard["summary"]["resolved_count"] == 1

    def test_dashboard_with_breached(self):
        esc = route_escalation("d1", ["ECOA"], "HIGH")
        with _store_lock:
            esc.sla_deadline = datetime.now(timezone.utc) - timedelta(hours=1)
        dashboard = get_sla_dashboard()
        assert dashboard["summary"]["breached_count"] == 1

    def test_escalation_to_dict_serialization(self):
        esc = route_escalation("d1", ["HIPAA"], "HIGH")
        d = escalation_to_dict(esc)
        assert d["decision_id"] == "d1"
        assert d["violation_type"] == "HIPAA"
        assert d["risk_level"] == "HIGH"
        assert d["assigned_reviewer"] == "Licensed Medical Professional"
        assert "sla_deadline" in d
        assert "escalation_id" in d
        assert d["status"] == "pending"
        assert d["resolved_at"] is None


# ═══════════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════════

class TestHITLEdgeCases:
    """Test boundary conditions and edge cases."""

    def test_case_insensitive_violation_type(self):
        esc = route_escalation("d1", ["ecoa"], "HIGH")
        assert esc.violation_type == ViolationType.ECOA

    def test_case_insensitive_risk_level(self):
        esc = route_escalation("d2", ["GENERAL"], "high")
        assert esc.risk_level == "HIGH"

    def test_escalation_id_is_unique(self):
        e1 = route_escalation("d1", ["ECOA"], "HIGH")
        e2 = route_escalation("d2", ["ECOA"], "HIGH")
        assert e1.escalation_id != e2.escalation_id

    def test_multiple_escalations_for_same_decision(self):
        e1 = route_escalation("same-decision", ["ECOA"], "HIGH")
        e2 = route_escalation("same-decision", ["HIPAA"], "MEDIUM")
        assert e1.escalation_id != e2.escalation_id
        # Both should exist
        dashboard = get_sla_dashboard()
        assert dashboard["total"] == 2
