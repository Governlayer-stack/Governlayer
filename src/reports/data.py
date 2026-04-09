"""Report data retrieval — queries real database records for report generation.

Provides functions to pull audit records, risk scores, evidence items, and
governance decisions from the database for use in compliance reports.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from src.models.database import AuditRecord, RiskScoreRecord, SessionLocal

logger = logging.getLogger("governlayer.reports")


def _get_db() -> Session:
    """Get a database session for report queries."""
    return SessionLocal()


class ReportData:
    """Container for real data pulled from the database for report generation."""

    def __init__(
        self,
        system_name: str,
        days: int = 90,
        db: Optional[Session] = None,
    ):
        self.system_name = system_name
        self.days = days
        self._db = db
        self._owns_db = False
        self._loaded = False

        # Data fields populated by load()
        self.audit_records: List[AuditRecord] = []
        self.risk_scores: List[RiskScoreRecord] = []
        self.evidence_items: List[Any] = []
        self.has_data = False

        # Computed summaries
        self.total_decisions = 0
        self.approved_count = 0
        self.denied_count = 0
        self.pending_count = 0
        self.escalated_count = 0
        self.compliance_rate = 0.0
        self.avg_risk_score = 0.0
        self.latest_risk_level = "unknown"
        self.risk_dimension_averages: Dict[str, float] = {}
        self.frameworks_audited: Dict[str, int] = {}
        self.evidence_by_framework: Dict[str, List[dict]] = {}
        self.evidence_by_control: Dict[str, List[dict]] = {}
        self.total_evidence = 0
        self.violations: List[dict] = []

    def load(self) -> "ReportData":
        """Load all data from the database."""
        if self._loaded:
            return self

        if not self._db:
            self._db = _get_db()
            self._owns_db = True

        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self.days)
            self._load_audit_records(cutoff)
            self._load_risk_scores(cutoff)
            self._load_evidence()
            self._compute_summaries()
            self._loaded = True
            self.has_data = bool(self.audit_records or self.risk_scores or self.evidence_items)
        except Exception as exc:
            logger.warning("Failed to load report data: %s", exc)
            self._loaded = True
            self.has_data = False
        finally:
            if self._owns_db and self._db:
                self._db.close()
                self._db = None

        return self

    def _load_audit_records(self, cutoff: datetime) -> None:
        """Load audit records for the system."""
        try:
            query = self._db.query(AuditRecord).filter(
                AuditRecord.created_at >= cutoff
            )
            if self.system_name and self.system_name != "organization":
                query = query.filter(AuditRecord.system_name == self.system_name)
            self.audit_records = query.order_by(AuditRecord.created_at.desc()).limit(500).all()
        except Exception as exc:
            logger.warning("Could not load audit records: %s", exc)
            self.audit_records = []

    def _load_risk_scores(self, cutoff: datetime) -> None:
        """Load risk score records for the system."""
        try:
            query = self._db.query(RiskScoreRecord).filter(
                RiskScoreRecord.created_at >= cutoff
            )
            if self.system_name and self.system_name != "organization":
                query = query.filter(RiskScoreRecord.system_name == self.system_name)
            self.risk_scores = query.order_by(RiskScoreRecord.created_at.desc()).limit(500).all()
        except Exception as exc:
            logger.warning("Could not load risk scores: %s", exc)
            self.risk_scores = []

    def _load_evidence(self) -> None:
        """Load evidence items from the evidence table."""
        try:
            from src.models.evidence import EvidenceItemDB
            self.evidence_items = (
                self._db.query(EvidenceItemDB)
                .order_by(EvidenceItemDB.collected_at.desc())
                .limit(1000)
                .all()
            )
        except Exception as exc:
            logger.warning("Could not load evidence items: %s", exc)
            self.evidence_items = []

    def _compute_summaries(self) -> None:
        """Compute summary statistics from loaded data."""
        # Audit record summaries
        self.total_decisions = len(self.audit_records)
        action_counts: Dict[str, int] = {}
        for rec in self.audit_records:
            action = (rec.governance_action or "PENDING").upper()
            action_counts[action] = action_counts.get(action, 0) + 1

            # Track frameworks audited
            if rec.frameworks_audited:
                for fw in rec.frameworks_audited.split(","):
                    fw = fw.strip()
                    if fw:
                        self.frameworks_audited[fw] = self.frameworks_audited.get(fw, 0) + 1

            # Track violations (high risk + denied/flagged)
            if rec.risk_level in ("high", "critical") or action in ("DENY", "FLAG", "ESCALATE"):
                self.violations.append({
                    "decision_id": rec.decision_id,
                    "system": rec.system_name,
                    "action": action,
                    "risk_level": rec.risk_level or "unknown",
                    "risk_score": rec.risk_score,
                    "created_at": rec.created_at.isoformat() if rec.created_at else "",
                })

        self.approved_count = action_counts.get("APPROVE", 0) + action_counts.get("APPROVED", 0)
        self.denied_count = action_counts.get("DENY", 0) + action_counts.get("DENIED", 0)
        self.pending_count = action_counts.get("PENDING", 0)
        self.escalated_count = action_counts.get("ESCALATE", 0) + action_counts.get("ESCALATED", 0)

        if self.total_decisions > 0:
            self.compliance_rate = round(
                (self.approved_count / self.total_decisions) * 100, 1
            )

        # Risk score summaries
        if self.risk_scores:
            scores = [r.overall_score for r in self.risk_scores if r.overall_score is not None]
            if scores:
                self.avg_risk_score = round(sum(scores) / len(scores), 1)

            latest = self.risk_scores[0]
            self.latest_risk_level = latest.risk_level or "unknown"

            # Dimension averages
            dims = {
                "privacy": [], "autonomy": [], "infrastructure": [],
                "oversight": [], "transparency": [], "fairness": [],
            }
            for r in self.risk_scores:
                for dim in dims:
                    val = getattr(r, f"{dim}_score", None)
                    if val is not None:
                        dims[dim].append(val)
            self.risk_dimension_averages = {
                dim: round(sum(vals) / len(vals), 1) if vals else 0.0
                for dim, vals in dims.items()
            }

        # Evidence summaries
        self.total_evidence = len(self.evidence_items)
        for item in self.evidence_items:
            fw = item.framework or "uncategorized"
            for fw_name in fw.split(","):
                fw_name = fw_name.strip()
                if fw_name:
                    self.evidence_by_framework.setdefault(fw_name, []).append(item)

            try:
                controls = json.loads(item.mapped_controls) if item.mapped_controls else []
            except (json.JSONDecodeError, TypeError):
                controls = []
            for cid in controls:
                self.evidence_by_control.setdefault(cid, []).append(item)

    def get_evidence_for_controls(self, control_prefixes: List[str]) -> List[dict]:
        """Get evidence items matching any of the given control prefixes."""
        results = []
        for cid, items in self.evidence_by_control.items():
            for prefix in control_prefixes:
                if cid.startswith(prefix):
                    for item in items:
                        results.append({
                            "control_id": cid,
                            "evidence_type": item.evidence_type,
                            "title": item.title,
                            "source": item.source or "",
                            "collected_at": item.collected_at.isoformat() if item.collected_at else "",
                        })
                    break
        return results[:20]  # limit for report size

    def executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary section for any report."""
        if not self.has_data:
            return {
                "data_available": False,
                "message": "No governance data collected yet. Run the governance pipeline to populate reports with real data.",
                "total_decisions": 0,
                "total_risk_assessments": 0,
                "total_evidence_items": 0,
            }

        return {
            "data_available": True,
            "reporting_period_days": self.days,
            "total_decisions": self.total_decisions,
            "total_risk_assessments": len(self.risk_scores),
            "total_evidence_items": self.total_evidence,
            "compliance_rate_pct": self.compliance_rate,
            "avg_risk_score": self.avg_risk_score,
            "latest_risk_level": self.latest_risk_level,
            "decisions_breakdown": {
                "approved": self.approved_count,
                "denied": self.denied_count,
                "pending": self.pending_count,
                "escalated": self.escalated_count,
            },
            "violations_count": len(self.violations),
            "frameworks_assessed": list(self.frameworks_audited.keys()),
        }

    def recommendations(self) -> List[str]:
        """Generate data-driven recommendations based on findings."""
        recs = []

        if not self.has_data:
            recs.append("Configure and run the governance pipeline to begin collecting compliance data.")
            recs.append("Connect evidence connectors (AWS, GitHub, etc.) for automated evidence collection.")
            return recs

        if self.compliance_rate < 80:
            recs.append(
                f"Compliance rate is {self.compliance_rate}% — investigate and remediate denied/escalated decisions."
            )
        if self.avg_risk_score > 60:
            recs.append(
                f"Average risk score is {self.avg_risk_score}/100 — prioritize risk reduction in high-scoring dimensions."
            )
        if len(self.violations) > 0:
            recs.append(
                f"{len(self.violations)} violations detected — review and resolve flagged governance decisions."
            )

        # Dimension-specific recommendations
        for dim, score in self.risk_dimension_averages.items():
            if score > 70:
                recs.append(f"{dim.title()} risk score is high ({score}/100) — requires attention.")

        if self.total_evidence == 0:
            recs.append("No evidence items collected — connect evidence connectors for continuous compliance.")

        if not recs:
            recs.append("Governance posture is healthy. Continue monitoring and regular assessments.")

        return recs
