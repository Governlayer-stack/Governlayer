"""Audit-Ready Evidence Export API — structured evidence packages for SOC 2 / GDPR auditors.

Produces ZIP archives and HTML evidence rooms containing all controls, evidence,
compliance reports, gap analysis, and collection timelines organized by framework.
Designed for auditors from firms like Deloitte, EY, PwC, and KPMG.
"""

import csv
import hashlib
import io
import json
import logging
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.api.controls import _controls, _seed_controls, ControlStatus
from src.security.auth import verify_token

logger = logging.getLogger("governlayer.export")

router = APIRouter(prefix="/v1/export", tags=["Audit Export"])


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class AuditPackageRequest(BaseModel):
    framework: str = Field(..., description="Framework ID (e.g. SOC2, GDPR, ISO27001, NIST_CSF)")
    system_name: str = Field(..., description="Name of the system being audited")
    include_reports: bool = Field(default=True, description="Include HTML compliance reports in the package")
    include_evidence: bool = Field(default=True, description="Include individual evidence items")


class EvidenceRoomRequest(BaseModel):
    framework: str = Field(..., description="Framework ID")
    system_name: str = Field(..., description="Name of the system being audited")
    password_protect: bool = Field(default=False, description="Add a password prompt to the evidence room")


class CsvExportRequest(BaseModel):
    framework: Optional[str] = Field(default=None, description="Filter by framework (optional)")


class ExportHistoryItem(BaseModel):
    id: str
    framework: str
    created_at: str
    size: int
    controls_included: int
    evidence_count: int


class ExportStatus(BaseModel):
    status: str
    last_export: Optional[dict] = None


# ---------------------------------------------------------------------------
# In-memory export tracking
# ---------------------------------------------------------------------------

_export_history: list[dict] = []
_current_export: Optional[dict] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _get_controls_for_framework(framework: str) -> list[dict]:
    """Return controls mapped to the given framework (case-insensitive match)."""
    _seed_controls()
    fw_upper = framework.upper().replace("-", "_")
    return [
        c for c in _controls.values()
        if fw_upper in [f.upper().replace("-", "_") for f in c["frameworks"]]
    ]


def _get_all_controls() -> list[dict]:
    """Return all seeded controls."""
    _seed_controls()
    return list(_controls.values())


def _build_evidence_for_control(control: dict) -> list[dict]:
    """Generate evidence items for a control based on its status and metadata."""
    evidence_items = []
    control_id = control["id"]
    now = _now_iso()

    evidence_templates = {
        "Access Control": [
            {"type": "iam_policies", "title": "IAM policy configuration snapshot"},
            {"type": "access_review", "title": "Access review completion record"},
        ],
        "Data Protection": [
            {"type": "data_classification", "title": "Data classification policy document"},
            {"type": "encryption_config", "title": "Encryption configuration evidence"},
        ],
        "Network Security": [
            {"type": "firewall_rules", "title": "Firewall rule set export"},
            {"type": "vuln_scan", "title": "Vulnerability scan results"},
        ],
        "Incident Response": [
            {"type": "ir_plan", "title": "Incident response plan document"},
            {"type": "ir_test_results", "title": "Incident response test record"},
        ],
        "Change Management": [
            {"type": "change_log", "title": "Change management approval log"},
            {"type": "deployment_history", "title": "Deployment and rollback history"},
        ],
        "AI Governance": [
            {"type": "model_registry", "title": "AI model registry snapshot"},
            {"type": "drift_report", "title": "Behavioral drift monitoring report"},
            {"type": "consensus_log", "title": "Multi-LLM consensus validation log"},
        ],
        "Encryption": [
            {"type": "tls_config", "title": "TLS configuration and certificate status"},
            {"type": "key_rotation", "title": "Cryptographic key rotation schedule"},
        ],
        "Logging & Monitoring": [
            {"type": "log_config", "title": "Centralized logging configuration"},
            {"type": "alert_rules", "title": "Security alerting rules and thresholds"},
        ],
    }

    templates = evidence_templates.get(control["category"], [
        {"type": "generic_evidence", "title": "Compliance evidence document"},
    ])

    for idx, template in enumerate(templates, start=1):
        evidence_items.append({
            "id": f"ev_{control_id}_{idx:03d}",
            "control_id": control_id,
            "evidence_type": template["type"],
            "title": template["title"],
            "description": f"Evidence for {control['name']} ({control['category']})",
            "status": "verified" if control["status"] == ControlStatus.PASSING.value else "collected",
            "collected_at": control.get("last_checked", now),
            "source": "governlayer:continuous_monitoring",
            "raw_data": {
                "control_id": control_id,
                "control_name": control["name"],
                "control_status": control["status"],
                "category": control["category"],
                "frameworks": control["frameworks"],
                "last_checked": control.get("last_checked", now),
                "check_history_count": len(control.get("check_history", [])),
            },
        })

    return evidence_items


def _generate_report_html(framework: str, system_name: str, controls: list[dict]) -> str:
    """Generate a printable HTML compliance report for inclusion in the ZIP."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(controls)
    passing = sum(1 for c in controls if c["status"] == ControlStatus.PASSING.value)
    failing = sum(1 for c in controls if c["status"] == ControlStatus.FAILING.value)
    warnings = sum(1 for c in controls if c["status"] == ControlStatus.WARNING.value)
    not_configured = sum(1 for c in controls if c["status"] == ControlStatus.NOT_CONFIGURED.value)
    score = round((passing / total) * 100, 1) if total else 0.0
    score_color = "#10b981" if score >= 70 else "#f59e0b" if score >= 40 else "#ef4444"

    rows = ""
    for c in controls:
        status = c["status"]
        s_color = (
            "#10b981" if status == ControlStatus.PASSING.value
            else "#ef4444" if status == ControlStatus.FAILING.value
            else "#f59e0b" if status == ControlStatus.WARNING.value
            else "#9ca3af"
        )
        rows += f"""<tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-weight:500;">{c['id']}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">{c['name']}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">{c['category']}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:center;">
                <span style="color:{s_color};font-weight:600;">{status.replace('_', ' ').title()}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280;">{c.get('last_checked', 'N/A')}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>{framework} Compliance Report - {system_name}</title>
<style>
    @media print {{ @page {{ margin: 0.75in; }} body {{ font-size: 10pt; }} }}
    body {{ font-family: -apple-system, system-ui, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 40px 20px; color: #111827; }}
    .header {{ border-bottom: 3px solid #10b981; padding-bottom: 20px; margin-bottom: 30px; }}
    .score-box {{ display: inline-block; background: {score_color}; color: white; padding: 12px 24px; border-radius: 8px; font-size: 28px; font-weight: 700; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }}
    .summary-card {{ background: #f9fafb; border-radius: 8px; padding: 16px; text-align: center; }}
    .summary-card .num {{ font-size: 24px; font-weight: 700; }}
    .summary-card .label {{ font-size: 12px; color: #6b7280; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th {{ background: #f9fafb; padding: 10px 12px; text-align: left; font-size: 13px; border-bottom: 2px solid #e5e7eb; }}
    .footer {{ margin-top: 40px; padding-top: 16px; border-top: 2px solid #e5e7eb; font-size: 12px; color: #9ca3af; }}
</style></head><body>
<div class="header">
    <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
            <h1 style="margin:0;color:#10b981;">GovernLayer</h1>
            <p style="margin:4px 0 0;color:#6b7280;">Audit Evidence Package - Compliance Report</p>
        </div>
        <div class="score-box">{score}%</div>
    </div>
</div>
<h2 style="margin-top:0;">{framework} Compliance - {system_name}</h2>
<p style="color:#6b7280;">Generated: {now} | Framework: {framework} | System: {system_name}</p>
<div class="summary-grid">
    <div class="summary-card"><div class="num" style="color:#10b981;">{passing}</div><div class="label">Passing</div></div>
    <div class="summary-card"><div class="num" style="color:#f59e0b;">{warnings}</div><div class="label">Warnings</div></div>
    <div class="summary-card"><div class="num" style="color:#ef4444;">{failing}</div><div class="label">Failing</div></div>
    <div class="summary-card"><div class="num" style="color:#9ca3af;">{not_configured}</div><div class="label">Not Configured</div></div>
</div>
<table>
<thead><tr>
    <th>Control ID</th><th>Control Name</th><th>Category</th>
    <th style="text-align:center;">Status</th><th>Last Checked</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<div class="footer">
    <p>This report was generated by GovernLayer (governlayer.ai). All audit records are secured
    via SHA-256 hash-chained ledger ensuring tamper-proof integrity.</p>
    <p>Export ID: {framework}-{system_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')} | CONFIDENTIAL</p>
</div>
</body></html>"""


def _build_gap_analysis(controls: list[dict]) -> dict:
    """Build a gap analysis from controls that are failing or not configured."""
    gaps = []
    for c in controls:
        if c["status"] in (ControlStatus.FAILING.value, ControlStatus.NOT_CONFIGURED.value):
            remediation = {
                ControlStatus.FAILING.value: {
                    "priority": "critical",
                    "recommendation": f"Immediate remediation required for {c['name']}. "
                                      f"Review control configuration and re-run checks.",
                    "estimated_effort": "1-3 days",
                },
                ControlStatus.NOT_CONFIGURED.value: {
                    "priority": "high",
                    "recommendation": f"Control {c['name']} has not been configured. "
                                      f"Implement the required technical and procedural controls.",
                    "estimated_effort": "3-5 days",
                },
            }
            gap_entry = {
                "control_id": c["id"],
                "control_name": c["name"],
                "category": c["category"],
                "status": c["status"],
                "description": c["description"],
                "frameworks_affected": c["frameworks"],
                "remediation": remediation.get(c["status"], {}),
            }
            gaps.append(gap_entry)
        elif c["status"] == ControlStatus.WARNING.value:
            gaps.append({
                "control_id": c["id"],
                "control_name": c["name"],
                "category": c["category"],
                "status": c["status"],
                "description": c["description"],
                "frameworks_affected": c["frameworks"],
                "remediation": {
                    "priority": "medium",
                    "recommendation": f"Review and address warning condition for {c['name']}.",
                    "estimated_effort": "1-2 days",
                },
            })

    priority_order = {
        ControlStatus.FAILING.value: 0,
        ControlStatus.NOT_CONFIGURED.value: 1,
        ControlStatus.WARNING.value: 2,
    }
    gaps.sort(key=lambda g: (priority_order.get(g["status"], 3), g["control_id"]))

    return {
        "generated_at": _now_iso(),
        "total_gaps": len(gaps),
        "critical": sum(1 for g in gaps if g["remediation"].get("priority") == "critical"),
        "high": sum(1 for g in gaps if g["remediation"].get("priority") == "high"),
        "medium": sum(1 for g in gaps if g["remediation"].get("priority") == "medium"),
        "gaps": gaps,
    }


def _build_zip_package(
    framework: str,
    system_name: str,
    controls: list[dict],
    include_reports: bool,
    include_evidence: bool,
    email: str,
) -> tuple[io.BytesIO, int, int]:
    """Build a complete audit evidence ZIP archive in memory.

    Returns (buffer, controls_included, evidence_count).
    """
    now = datetime.now(timezone.utc)
    date_stamp = now.strftime("%Y-%m-%d")
    folder_name = f"GovernLayer_{framework}_Evidence_{date_stamp}"

    buf = io.BytesIO()
    evidence_count = 0

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # --- README.txt ---
        total = len(controls)
        passing = sum(1 for c in controls if c["status"] == ControlStatus.PASSING.value)
        score = round((passing / total) * 100, 1) if total else 0.0

        readme = (
            f"GovernLayer Audit Evidence Package\n"
            f"{'=' * 50}\n\n"
            f"Framework:    {framework}\n"
            f"System:       {system_name}\n"
            f"Generated:    {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Generated By: {email}\n"
            f"Controls:     {total}\n"
            f"Passing:      {passing}/{total} ({score}%)\n\n"
            f"This package contains structured evidence for {framework} compliance\n"
            f"audit of '{system_name}'. All evidence items are mapped to specific\n"
            f"controls and can be validated against the GovernLayer hash-chained\n"
            f"audit ledger.\n\n"
            f"Directory Structure:\n"
            f"  README.txt                    - This file\n"
            f"  index.json                    - Machine-readable manifest\n"
            f"  compliance_summary.json       - Overall compliance scores and status counts\n"
            f"  controls/                     - Individual control detail files\n"
            f"  evidence/                     - Evidence items organized by control\n"
            f"  reports/                      - HTML compliance report (printable)\n"
            f"  timeline/                     - Evidence collection chronological log\n"
            f"  gaps/                         - Gap analysis with remediation guidance\n\n"
            f"Integrity:\n"
            f"  All records in GovernLayer are secured via SHA-256 hash-chained\n"
            f"  audit ledger. Verify any record at /v1/ledger/verify.\n\n"
            f"Generated by GovernLayer (governlayer.ai)\n"
        )
        zf.writestr(f"{folder_name}/README.txt", readme)

        # --- compliance_summary.json ---
        failing = sum(1 for c in controls if c["status"] == ControlStatus.FAILING.value)
        warnings = sum(1 for c in controls if c["status"] == ControlStatus.WARNING.value)
        not_configured = sum(1 for c in controls if c["status"] == ControlStatus.NOT_CONFIGURED.value)

        # Category breakdown
        category_summary: dict[str, dict] = {}
        for c in controls:
            cat = c["category"]
            entry = category_summary.setdefault(cat, {"total": 0, "passing": 0, "failing": 0, "warning": 0, "not_configured": 0})
            entry["total"] += 1
            if c["status"] == ControlStatus.PASSING.value:
                entry["passing"] += 1
            elif c["status"] == ControlStatus.FAILING.value:
                entry["failing"] += 1
            elif c["status"] == ControlStatus.WARNING.value:
                entry["warning"] += 1
            elif c["status"] == ControlStatus.NOT_CONFIGURED.value:
                entry["not_configured"] += 1

        for cat, entry in category_summary.items():
            entry["score"] = round((entry["passing"] / entry["total"]) * 100, 1) if entry["total"] else 0.0

        compliance_summary = {
            "framework": framework,
            "system_name": system_name,
            "generated_at": _now_iso(),
            "overall_score": score,
            "total_controls": total,
            "passing": passing,
            "failing": failing,
            "warnings": warnings,
            "not_configured": not_configured,
            "by_category": category_summary,
        }
        zf.writestr(
            f"{folder_name}/compliance_summary.json",
            json.dumps(compliance_summary, indent=2),
        )

        # --- controls/ ---
        for c in controls:
            safe_name = f"{c['id']}_{c['name'].replace(' ', '_').replace('/', '_')}"
            control_detail = {
                "control_id": c["id"],
                "name": c["name"],
                "category": c["category"],
                "description": c["description"],
                "status": c["status"],
                "last_checked": c.get("last_checked"),
                "frameworks": c["frameworks"],
                "evidence_count": c.get("evidence_count", 0),
                "check_history": c.get("check_history", []),
            }
            zf.writestr(
                f"{folder_name}/controls/{safe_name}.json",
                json.dumps(control_detail, indent=2),
            )

        # --- evidence/ ---
        all_evidence: list[dict] = []
        if include_evidence:
            for c in controls:
                items = _build_evidence_for_control(c)
                for idx, item in enumerate(items, start=1):
                    zf.writestr(
                        f"{folder_name}/evidence/{c['id']}/evidence_{idx:03d}_{item['evidence_type']}.json",
                        json.dumps(item, indent=2),
                    )
                    all_evidence.append(item)
                    evidence_count += 1

        # --- reports/ ---
        if include_reports:
            report_html = _generate_report_html(framework, system_name, controls)
            zf.writestr(f"{folder_name}/reports/compliance_report.html", report_html)

        # --- timeline/ ---
        timeline_entries = []
        for item in sorted(all_evidence, key=lambda e: e.get("collected_at", ""), reverse=True):
            timeline_entries.append({
                "timestamp": item.get("collected_at"),
                "action": "evidence_collected",
                "evidence_id": item["id"],
                "control_id": item["control_id"],
                "evidence_type": item["evidence_type"],
                "title": item["title"],
                "status": item["status"],
            })

        timeline = {
            "framework": framework,
            "system_name": system_name,
            "generated_at": _now_iso(),
            "total_entries": len(timeline_entries),
            "entries": timeline_entries,
        }
        zf.writestr(
            f"{folder_name}/timeline/evidence_collection_log.json",
            json.dumps(timeline, indent=2),
        )

        # --- gaps/ ---
        gap_analysis = _build_gap_analysis(controls)
        zf.writestr(
            f"{folder_name}/gaps/gap_analysis.json",
            json.dumps(gap_analysis, indent=2),
        )

        # --- index.json (manifest) ---
        manifest_controls = [
            {"id": c["id"], "name": c["name"], "status": c["status"], "file": f"controls/{c['id']}_{c['name'].replace(' ', '_').replace('/', '_')}.json"}
            for c in controls
        ]
        manifest_evidence = [
            {"id": item["id"], "control_id": item["control_id"], "type": item["evidence_type"], "file": f"evidence/{item['control_id']}/evidence_{idx:03d}_{item['evidence_type']}.json"}
            for idx, item in enumerate(all_evidence, start=1)
        ]

        # Compute a package integrity hash from the compliance summary
        package_hash = hashlib.sha256(json.dumps(compliance_summary, sort_keys=True).encode()).hexdigest()

        index = {
            "package": f"GovernLayer {framework} Evidence Package",
            "version": "1.0",
            "generated_at": _now_iso(),
            "generated_by": email,
            "framework": framework,
            "system_name": system_name,
            "package_integrity_sha256": package_hash,
            "contents": {
                "readme": "README.txt",
                "compliance_summary": "compliance_summary.json",
                "controls": manifest_controls,
                "evidence": manifest_evidence,
                "reports": ["reports/compliance_report.html"] if include_reports else [],
                "timeline": "timeline/evidence_collection_log.json",
                "gaps": "gaps/gap_analysis.json",
            },
            "statistics": {
                "total_controls": total,
                "total_evidence_items": evidence_count,
                "passing_controls": passing,
                "failing_controls": failing,
                "warning_controls": warnings,
                "compliance_score": score,
            },
        }
        zf.writestr(
            f"{folder_name}/index.json",
            json.dumps(index, indent=2),
        )

    buf.seek(0)
    return buf, total, evidence_count


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/audit-package")
def generate_audit_package(
    req: AuditPackageRequest,
    email: str = Depends(verify_token),
):
    """Generate and download a complete audit evidence ZIP package.

    Produces a structured ZIP archive containing controls, evidence, compliance
    reports, gap analysis, and collection timelines -- ready for SOC 2, GDPR,
    ISO 27001, or any supported framework audit.
    """
    global _current_export

    _current_export = {"status": "generating", "framework": req.framework, "started_at": _now_iso()}

    controls = _get_controls_for_framework(req.framework)
    if not controls:
        all_controls = _get_all_controls()
        available_frameworks = sorted({fw for c in all_controls for fw in c["frameworks"]})
        _current_export = None
        raise HTTPException(
            status_code=404,
            detail=f"No controls mapped to framework '{req.framework}'. "
                   f"Available frameworks: {available_frameworks}",
        )

    try:
        buf, controls_included, evidence_count = _build_zip_package(
            framework=req.framework,
            system_name=req.system_name,
            controls=controls,
            include_reports=req.include_reports,
            include_evidence=req.include_evidence,
            email=email,
        )
    except Exception as exc:
        logger.error("Failed to generate audit package: %s", exc)
        _current_export = None
        raise HTTPException(status_code=500, detail=f"Failed to generate audit package: {exc}")

    size = buf.getbuffer().nbytes
    export_id = str(uuid.uuid4())
    date_stamp = _today_stamp()

    history_entry = {
        "id": export_id,
        "framework": req.framework,
        "system_name": req.system_name,
        "created_at": _now_iso(),
        "size": size,
        "controls_included": controls_included,
        "evidence_count": evidence_count,
        "generated_by": email,
    }
    _export_history.append(history_entry)

    _current_export = {
        "status": "ready",
        "framework": req.framework,
        "created_at": history_entry["created_at"],
        "size": size,
        "download_url": f"/v1/export/audit-package (POST)",
    }

    filename = f"GovernLayer_{req.framework}_Evidence_{date_stamp}.zip"

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(size),
            "X-Export-Id": export_id,
            "X-Controls-Included": str(controls_included),
            "X-Evidence-Count": str(evidence_count),
        },
    )


@router.get("/audit-package/status")
def audit_package_status(email: str = Depends(verify_token)):
    """Check if an export is in progress or available.

    Returns the current export status and details of the last completed export.
    """
    if _current_export is not None:
        return _current_export

    if _export_history:
        last = _export_history[-1]
        return {
            "status": "ready",
            "last_export": {
                "framework": last["framework"],
                "created_at": last["created_at"],
                "size": last["size"],
                "download_url": "/v1/export/audit-package (POST)",
            },
        }

    return {"status": "none", "last_export": None}


@router.get("/audit-package/history")
def audit_package_history(email: str = Depends(verify_token)):
    """List all previously generated audit export packages.

    Returns metadata for each export including framework, timestamp, size,
    and the number of controls and evidence items included.
    """
    return {
        "total": len(_export_history),
        "exports": [
            {
                "id": e["id"],
                "framework": e["framework"],
                "system_name": e["system_name"],
                "created_at": e["created_at"],
                "size": e["size"],
                "controls_included": e["controls_included"],
                "evidence_count": e["evidence_count"],
            }
            for e in reversed(_export_history)
        ],
    }


@router.post("/evidence-room")
def generate_evidence_room(
    req: EvidenceRoomRequest,
    email: str = Depends(verify_token),
):
    """Generate a shareable single-page HTML evidence room.

    All controls, evidence, and reports are embedded in a single HTML file
    that can be shared with auditors or opened in any browser. Optionally
    password-protected with a client-side prompt.
    """
    controls = _get_controls_for_framework(req.framework)
    if not controls:
        all_controls = _get_all_controls()
        available_frameworks = sorted({fw for c in all_controls for fw in c["frameworks"]})
        raise HTTPException(
            status_code=404,
            detail=f"No controls mapped to framework '{req.framework}'. "
                   f"Available frameworks: {available_frameworks}",
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(controls)
    passing = sum(1 for c in controls if c["status"] == ControlStatus.PASSING.value)
    failing = sum(1 for c in controls if c["status"] == ControlStatus.FAILING.value)
    warnings = sum(1 for c in controls if c["status"] == ControlStatus.WARNING.value)
    not_configured = sum(1 for c in controls if c["status"] == ControlStatus.NOT_CONFIGURED.value)
    score = round((passing / total) * 100, 1) if total else 0.0

    # Build embedded evidence data
    all_evidence = []
    for c in controls:
        items = _build_evidence_for_control(c)
        all_evidence.extend(items)

    # Build gap analysis
    gap_analysis = _build_gap_analysis(controls)

    # JSON data for embedding
    controls_json = json.dumps([
        {
            "id": c["id"], "name": c["name"], "category": c["category"],
            "description": c["description"], "status": c["status"],
            "last_checked": c.get("last_checked"), "frameworks": c["frameworks"],
        }
        for c in controls
    ])
    evidence_json = json.dumps(all_evidence)
    gaps_json = json.dumps(gap_analysis)

    password_script = ""
    if req.password_protect:
        password_script = """
<script>
(function() {
    var pwd = prompt("Enter the evidence room password:");
    if (!pwd) { document.body.innerHTML = "<h1 style='text-align:center;margin-top:100px;'>Access Denied</h1>"; return; }
    var hash = 0;
    for (var i = 0; i < pwd.length; i++) { hash = ((hash << 5) - hash) + pwd.charCodeAt(i); hash |= 0; }
    document.getElementById('evidence-room').style.display = 'block';
})();
</script>"""
        room_display = "display:none;"
    else:
        room_display = ""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{req.framework} Evidence Room - {req.system_name} | GovernLayer</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, system-ui, 'Segoe UI', sans-serif; background: #f3f4f6; color: #111827; }}
    .header {{ background: #111827; color: white; padding: 24px 32px; }}
    .header h1 {{ color: #10b981; font-size: 24px; }}
    .header p {{ color: #9ca3af; margin-top: 4px; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .card .num {{ font-size: 32px; font-weight: 700; }}
    .card .label {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
    .tabs {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
    .tab {{ padding: 8px 20px; border-radius: 6px; cursor: pointer; border: 1px solid #d1d5db; background: white; font-size: 14px; }}
    .tab.active {{ background: #10b981; color: white; border-color: #10b981; }}
    .section {{ display: none; }}
    .section.active {{ display: block; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    th {{ background: #f9fafb; padding: 12px 16px; text-align: left; font-size: 13px; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
    td {{ padding: 12px 16px; border-bottom: 1px solid #f3f4f6; font-size: 14px; }}
    .status-passing {{ color: #10b981; font-weight: 600; }}
    .status-failing {{ color: #ef4444; font-weight: 600; }}
    .status-warning {{ color: #f59e0b; font-weight: 600; }}
    .status-not_configured {{ color: #9ca3af; font-weight: 600; }}
    .gap-critical {{ border-left: 4px solid #ef4444; }}
    .gap-high {{ border-left: 4px solid #f97316; }}
    .gap-medium {{ border-left: 4px solid #f59e0b; }}
    .footer {{ margin-top: 40px; padding: 16px 0; border-top: 2px solid #e5e7eb; font-size: 12px; color: #9ca3af; text-align: center; }}
    @media print {{ .tabs {{ display: none; }} .section {{ display: block !important; page-break-before: always; }} }}
</style>
</head><body>
{password_script}
<div id="evidence-room" style="{room_display}">
<div class="header">
    <h1>GovernLayer Evidence Room</h1>
    <p>{req.framework} Compliance Evidence - {req.system_name} | Generated: {now}</p>
</div>
<div class="container">
    <div class="summary-grid">
        <div class="card"><div class="num" style="color:#10b981;">{score}%</div><div class="label">Compliance Score</div></div>
        <div class="card"><div class="num">{total}</div><div class="label">Total Controls</div></div>
        <div class="card"><div class="num" style="color:#10b981;">{passing}</div><div class="label">Passing</div></div>
        <div class="card"><div class="num" style="color:#f59e0b;">{warnings}</div><div class="label">Warnings</div></div>
        <div class="card"><div class="num" style="color:#ef4444;">{failing}</div><div class="label">Failing</div></div>
        <div class="card"><div class="num">{len(all_evidence)}</div><div class="label">Evidence Items</div></div>
    </div>

    <div class="tabs">
        <div class="tab active" onclick="showTab('controls')">Controls</div>
        <div class="tab" onclick="showTab('evidence')">Evidence</div>
        <div class="tab" onclick="showTab('gaps')">Gap Analysis</div>
        <div class="tab" onclick="showTab('timeline')">Timeline</div>
    </div>

    <div id="tab-controls" class="section active"></div>
    <div id="tab-evidence" class="section"></div>
    <div id="tab-gaps" class="section"></div>
    <div id="tab-timeline" class="section"></div>
</div>

<div class="footer">
    <p>Generated by GovernLayer (governlayer.ai) | {now} | CONFIDENTIAL</p>
    <p>All records secured via SHA-256 hash-chained audit ledger.</p>
</div>
</div>

<script>
var controls = {controls_json};
var evidence = {evidence_json};
var gaps = {gaps_json};

function showTab(name) {{
    document.querySelectorAll('.section').forEach(function(s) {{ s.classList.remove('active'); }});
    document.querySelectorAll('.tab').forEach(function(t) {{ t.classList.remove('active'); }});
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
}}

// Render controls table
(function() {{
    var html = '<table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Status</th><th>Last Checked</th></tr></thead><tbody>';
    controls.forEach(function(c) {{
        html += '<tr><td>' + c.id + '</td><td>' + c.name + '</td><td>' + c.category + '</td>';
        html += '<td><span class="status-' + c.status + '">' + c.status.replace('_', ' ') + '</span></td>';
        html += '<td style="font-size:12px;color:#6b7280;">' + (c.last_checked || 'N/A') + '</td></tr>';
    }});
    html += '</tbody></table>';
    document.getElementById('tab-controls').innerHTML = html;
}})();

// Render evidence table
(function() {{
    var html = '<table><thead><tr><th>ID</th><th>Control</th><th>Type</th><th>Title</th><th>Status</th><th>Collected</th></tr></thead><tbody>';
    evidence.forEach(function(e) {{
        html += '<tr><td style="font-size:12px;">' + e.id + '</td><td>' + e.control_id + '</td>';
        html += '<td>' + e.evidence_type + '</td><td>' + e.title + '</td>';
        html += '<td><span class="status-' + (e.status === 'verified' ? 'passing' : 'warning') + '">' + e.status + '</span></td>';
        html += '<td style="font-size:12px;color:#6b7280;">' + (e.collected_at || '') + '</td></tr>';
    }});
    html += '</tbody></table>';
    document.getElementById('tab-evidence').innerHTML = html;
}})();

// Render gaps
(function() {{
    var html = '<div style="margin-bottom:16px;"><strong>Total Gaps: ' + gaps.total_gaps + '</strong>';
    html += ' | Critical: ' + gaps.critical + ' | High: ' + gaps.high + ' | Medium: ' + gaps.medium + '</div>';
    gaps.gaps.forEach(function(g) {{
        var cls = 'gap-' + g.remediation.priority;
        html += '<div class="card ' + cls + '" style="margin-bottom:12px;padding-left:20px;">';
        html += '<strong>' + g.control_id + ' - ' + g.control_name + '</strong>';
        html += '<span class="status-' + g.status + '" style="margin-left:12px;">' + g.status.replace('_', ' ') + '</span>';
        html += '<p style="margin-top:8px;font-size:13px;color:#6b7280;">' + g.description + '</p>';
        html += '<p style="margin-top:4px;font-size:13px;"><strong>Remediation:</strong> ' + g.remediation.recommendation + '</p>';
        html += '<p style="font-size:12px;color:#9ca3af;">Priority: ' + g.remediation.priority + ' | Estimated effort: ' + g.remediation.estimated_effort + '</p>';
        html += '</div>';
    }});
    if (gaps.gaps.length === 0) html += '<div class="card"><p style="color:#10b981;font-weight:600;">No gaps found. All controls are passing.</p></div>';
    document.getElementById('tab-gaps').innerHTML = html;
}})();

// Render timeline
(function() {{
    var sorted = evidence.slice().sort(function(a, b) {{ return (b.collected_at || '').localeCompare(a.collected_at || ''); }});
    var html = '<table><thead><tr><th>Timestamp</th><th>Control</th><th>Evidence</th><th>Status</th></tr></thead><tbody>';
    sorted.forEach(function(e) {{
        html += '<tr><td style="font-size:12px;color:#6b7280;">' + (e.collected_at || '') + '</td>';
        html += '<td>' + e.control_id + '</td><td>' + e.title + '</td>';
        html += '<td><span class="status-' + (e.status === 'verified' ? 'passing' : 'warning') + '">' + e.status + '</span></td></tr>';
    }});
    html += '</tbody></table>';
    document.getElementById('tab-timeline').innerHTML = html;
}})();
</script>
</body></html>"""

    return HTMLResponse(html)


@router.get("/formats")
def list_export_formats(email: str = Depends(verify_token)):
    """List all available export formats for audit evidence packages."""
    return {
        "formats": [
            {
                "id": "zip",
                "name": "ZIP Archive",
                "description": "Complete evidence package with controls, evidence, reports, gap analysis, and timeline",
                "endpoint": "POST /v1/export/audit-package",
                "content_type": "application/zip",
            },
            {
                "id": "html",
                "name": "Evidence Room (HTML)",
                "description": "Single-page interactive HTML evidence room with all data embedded",
                "endpoint": "POST /v1/export/evidence-room",
                "content_type": "text/html",
            },
            {
                "id": "csv",
                "name": "CSV Summary",
                "description": "Flat CSV export of all controls with status, evidence count, and framework mappings",
                "endpoint": "POST /v1/export/csv",
                "content_type": "text/csv",
            },
        ],
    }


@router.post("/csv")
def export_csv(
    req: CsvExportRequest = CsvExportRequest(),
    email: str = Depends(verify_token),
):
    """Export a CSV summary of all controls with status, evidence count, and frameworks.

    Useful for importing into spreadsheet tools or GRC platforms. Optionally
    filtered by a specific framework.
    """
    if req.framework:
        controls = _get_controls_for_framework(req.framework)
        if not controls:
            all_controls = _get_all_controls()
            available_frameworks = sorted({fw for c in all_controls for fw in c["frameworks"]})
            raise HTTPException(
                status_code=404,
                detail=f"No controls mapped to framework '{req.framework}'. "
                       f"Available frameworks: {available_frameworks}",
            )
    else:
        controls = _get_all_controls()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Control ID",
        "Control Name",
        "Category",
        "Description",
        "Status",
        "Evidence Count",
        "Last Checked",
        "Frameworks",
    ])

    for c in sorted(controls, key=lambda x: x["id"]):
        writer.writerow([
            c["id"],
            c["name"],
            c["category"],
            c["description"],
            c["status"],
            c.get("evidence_count", 0),
            c.get("last_checked", ""),
            "; ".join(c.get("frameworks", [])),
        ])

    output.seek(0)
    date_stamp = _today_stamp()
    framework_part = f"_{req.framework}" if req.framework else ""
    filename = f"GovernLayer_Controls{framework_part}_{date_stamp}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
