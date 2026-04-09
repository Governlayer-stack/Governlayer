"""Evidence Auto-Collection API — continuous compliance evidence gathering.

Supports real connectors (AWS, GitHub, Generic REST) that make actual API calls,
plus simulated connectors for services without real implementations yet.
All evidence is persisted to the database via EvidenceItemDB/EvidenceConnectorDB.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.models.database import get_db
from src.models.evidence import EvidenceConnectorDB, EvidenceItemDB, EvidenceScheduleDB
from src.security.api_key_auth import AuthContext, require_scope

logger = logging.getLogger("governlayer.evidence")

router = APIRouter(prefix="/v1/evidence", tags=["Evidence Collection"])


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ConnectorStatus(str, Enum):
    AVAILABLE = "available"
    CONNECTED = "connected"
    COLLECTING = "collecting"
    ERROR = "error"


class EvidenceStatus(str, Enum):
    COLLECTED = "collected"
    VERIFIED = "verified"
    STALE = "stale"
    FAILED = "failed"


class CollectionFrequency(str, Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class ConnectorInfo(BaseModel):
    name: str
    category: str
    status: ConnectorStatus
    evidence_types: list[str]
    last_sync: Optional[str] = None
    description: str


class ConnectRequest(BaseModel):
    connector_name: str
    credentials: dict = Field(
        default_factory=dict,
        description="Connector-specific credentials (e.g. aws_access_key, github_token)",
    )
    connector_type: Optional[str] = Field(
        None,
        description="Override connector type for real connectors (aws, github, rest). Defaults to connector_name.",
    )


class CollectRequest(BaseModel):
    connector_name: str


class EvidenceItem(BaseModel):
    id: str
    connector: str
    evidence_type: str
    title: str
    description: str
    status: EvidenceStatus
    collected_at: str
    raw_data: dict
    mapped_controls: list[str] = Field(default_factory=list)
    source: str


class MapRequest(BaseModel):
    evidence_id: str
    control_ids: list[str]


class ScheduleRequest(BaseModel):
    connector_name: str
    frequency: CollectionFrequency


class TestConnectionRequest(BaseModel):
    connector_name: str


# ---------------------------------------------------------------------------
# Connector Registry (static metadata)
# ---------------------------------------------------------------------------

CONNECTORS: dict[str, ConnectorInfo] = {
    "aws": ConnectorInfo(
        name="aws",
        category="Cloud Infrastructure",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["iam_policies", "cloudtrail_events", "security_groups"],
        description="Amazon Web Services — IAM, CloudTrail, EC2 Security Groups (real API)",
    ),
    "github": ConnectorInfo(
        name="github",
        category="Source Control",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["branch_protection", "audit_log", "security_alerts"],
        description="GitHub — repo security, branch rules, Dependabot alerts (real API)",
    ),
    "rest": ConnectorInfo(
        name="rest",
        category="Generic Integration",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["api_response"],
        description="Generic REST API — configurable endpoints for Jira, ServiceNow, Splunk, etc. (real API)",
    ),
    "postgresql": ConnectorInfo(
        name="postgresql",
        category="Database",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["ssl_config", "password_policy", "audit_logging", "user_privileges", "encryption_at_rest"],
        description="PostgreSQL — SSL, auth policies, audit logging, encryption config",
    ),
    "docker": ConnectorInfo(
        name="docker",
        category="Container Runtime",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["image_vulnerabilities", "no_root_containers", "signed_images", "resource_limits", "network_policies"],
        description="Docker — image scanning, runtime security, resource constraints",
    ),
    "kubernetes": ConnectorInfo(
        name="kubernetes",
        category="Container Orchestration",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["rbac_policies", "network_policies", "pod_security", "secrets_encryption", "audit_logging"],
        description="Kubernetes — RBAC, network policies, pod security standards, secrets",
    ),
    "okta": ConnectorInfo(
        name="okta",
        category="Identity & Access",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["sso_config", "mfa_enrollment", "password_policy", "session_policy", "admin_audit"],
        description="Okta — SSO configuration, MFA enrollment rates, password policies",
    ),
    "google_workspace": ConnectorInfo(
        name="google_workspace",
        category="Productivity",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["admin_policies", "drive_sharing", "login_audit", "mobile_mgmt", "dlp_rules"],
        description="Google Workspace — admin policies, sharing controls, DLP, mobile management",
    ),
    "slack": ConnectorInfo(
        name="slack",
        category="Communication",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["dlp_settings", "retention_policies", "app_approvals", "channel_mgmt", "export_settings"],
        description="Slack — DLP settings, retention policies, approved apps, export controls",
    ),
    "datadog": ConnectorInfo(
        name="datadog",
        category="Observability",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["monitors_config", "slo_definitions", "dashboard_coverage", "alert_routing", "log_retention"],
        description="Datadog — monitors, SLOs, alert routing, log retention policies",
    ),
}

# Connector types that have real implementations
REAL_CONNECTOR_TYPES = {"aws", "github", "rest"}


# ---------------------------------------------------------------------------
# Compliance Controls Reference (for coverage mapping)
# ---------------------------------------------------------------------------

COMPLIANCE_CONTROLS = [
    {"id": "SOC2-CC6.1", "name": "Logical & Physical Access", "framework": "SOC2"},
    {"id": "SOC2-CC6.3", "name": "Role-Based Access", "framework": "SOC2"},
    {"id": "SOC2-CC6.6", "name": "Boundary Protection", "framework": "SOC2"},
    {"id": "SOC2-CC6.7", "name": "Data Protection", "framework": "SOC2"},
    {"id": "SOC2-CC7.1", "name": "System Monitoring", "framework": "SOC2"},
    {"id": "SOC2-CC7.2", "name": "Anomaly Detection", "framework": "SOC2"},
    {"id": "SOC2-CC7.4", "name": "Incident Response", "framework": "SOC2"},
    {"id": "SOC2-CC8.1", "name": "Change Management", "framework": "SOC2"},
    {"id": "ISO27001-A.8.2", "name": "Information Classification", "framework": "ISO27001"},
    {"id": "ISO27001-A.9.2", "name": "User Access Management", "framework": "ISO27001"},
    {"id": "ISO27001-A.9.4", "name": "System Access Control", "framework": "ISO27001"},
    {"id": "ISO27001-A.10.1", "name": "Cryptographic Controls", "framework": "ISO27001"},
    {"id": "ISO27001-A.12.1", "name": "Operational Procedures", "framework": "ISO27001"},
    {"id": "ISO27001-A.12.4", "name": "Logging & Monitoring", "framework": "ISO27001"},
    {"id": "ISO27001-A.12.6", "name": "Vulnerability Management", "framework": "ISO27001"},
    {"id": "ISO27001-A.13.1", "name": "Network Security", "framework": "ISO27001"},
    {"id": "ISO27001-A.14.2", "name": "Secure Development", "framework": "ISO27001"},
    {"id": "ISO27001-A.17.1", "name": "Business Continuity", "framework": "ISO27001"},
    {"id": "NIST-AC-3", "name": "Access Enforcement", "framework": "NIST"},
    {"id": "NIST-AC-6", "name": "Least Privilege", "framework": "NIST"},
    {"id": "NIST-AU-2", "name": "Audit Events", "framework": "NIST"},
    {"id": "NIST-AU-11", "name": "Audit Record Retention", "framework": "NIST"},
    {"id": "NIST-CM-3", "name": "Configuration Change Control", "framework": "NIST"},
    {"id": "NIST-CM-7", "name": "Least Functionality", "framework": "NIST"},
    {"id": "NIST-CP-2", "name": "Contingency Plan", "framework": "NIST"},
    {"id": "NIST-IA-2", "name": "Identification & Authentication", "framework": "NIST"},
    {"id": "NIST-IA-5", "name": "Authenticator Management", "framework": "NIST"},
    {"id": "NIST-SC-6", "name": "Resource Availability", "framework": "NIST"},
    {"id": "NIST-SC-7", "name": "Boundary Protection", "framework": "NIST"},
    {"id": "NIST-SC-8", "name": "Transmission Confidentiality", "framework": "NIST"},
    {"id": "NIST-SC-28", "name": "Protection of Data at Rest", "framework": "NIST"},
    {"id": "NIST-SI-2", "name": "Flaw Remediation", "framework": "NIST"},
    {"id": "NIST-SI-4", "name": "System Monitoring", "framework": "NIST"},
    {"id": "HIPAA-164.312(b)", "name": "Audit Controls", "framework": "HIPAA"},
    {"id": "HIPAA-164.312(d)", "name": "Person Authentication", "framework": "HIPAA"},
    {"id": "HIPAA-164.312(e)", "name": "Transmission Security", "framework": "HIPAA"},
    {"id": "HIPAA-164.530(j)", "name": "Record Retention", "framework": "HIPAA"},
    {"id": "GDPR-Art32", "name": "Security of Processing", "framework": "GDPR"},
    {"id": "OWASP-A06", "name": "Vulnerable Components", "framework": "OWASP"},
    {"id": "OWASP-A07", "name": "Auth Failures", "framework": "OWASP"},
    {"id": "CIS-Docker-5.1", "name": "Container Runtime Security", "framework": "CIS"},
    {"id": "CIS-K8s-5.2", "name": "Pod Security Policies", "framework": "CIS"},
]


# ---------------------------------------------------------------------------
# Simulated Evidence Generators (fallback for non-real connectors)
# ---------------------------------------------------------------------------

def _generate_simulated_evidence(connector_name: str) -> list[dict]:
    """Generate simulated evidence for connectors without real API implementations."""
    now = datetime.now(timezone.utc)
    generators = {
        "postgresql": _gen_postgresql,
        "docker": _gen_docker,
        "kubernetes": _gen_kubernetes,
        "okta": _gen_okta,
        "google_workspace": _gen_google_workspace,
        "slack": _gen_slack,
        "datadog": _gen_datadog,
    }
    gen = generators.get(connector_name)
    if not gen:
        return []
    return gen(now)


def _sim_item(connector: str, etype: str, title: str, desc: str,
              raw: dict, controls: list[str], ts: datetime) -> dict:
    return {
        "evidence_type": etype,
        "title": title,
        "description": desc,
        "raw_data": raw,
        "mapped_controls": controls,
        "source": f"{connector}:simulated",
        "framework": ",".join(set(c.split("-")[0] for c in controls)),
    }


def _gen_postgresql(ts: datetime) -> list[dict]:
    return [
        _sim_item("postgresql", "ssl_config", "SSL/TLS enforced for all connections",
                   "PostgreSQL configured with ssl=on, minimum TLS 1.2",
                   {"ssl_enabled": True, "ssl_min_version": "TLSv1.2", "connections_ssl": 148, "connections_plain": 0},
                   ["SOC2-CC6.7", "ISO27001-A.13.1", "NIST-SC-8", "HIPAA-164.312(e)"], ts),
        _sim_item("postgresql", "password_policy", "Strong password authentication policy",
                   "scram-sha-256 auth, no trust/md5 in pg_hba.conf",
                   {"auth_method": "scram-sha-256", "pg_hba_trust_entries": 0, "pg_hba_md5_entries": 0},
                   ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-5"], ts),
        _sim_item("postgresql", "audit_logging", "Database audit logging active",
                   "pgaudit extension enabled, logging DDL, log_connections=on",
                   {"pgaudit_enabled": True, "log_statement": "ddl", "log_connections": True, "log_retention_days": 90},
                   ["SOC2-CC7.2", "ISO27001-A.12.4", "NIST-AU-2", "HIPAA-164.312(b)"], ts),
        _sim_item("postgresql", "user_privileges", "Least-privilege database roles",
                   "14 roles reviewed; no excess superuser accounts",
                   {"total_roles": 14, "superusers": 1, "app_roles_readonly": 8, "orphaned_roles": 0},
                   ["SOC2-CC6.3", "ISO27001-A.9.2", "NIST-AC-6"], ts),
    ]


def _gen_docker(ts: datetime) -> list[dict]:
    return [
        _sim_item("docker", "no_root_containers", "Containers running as non-root",
                   "18/18 production containers run as non-root user",
                   {"total_containers": 18, "non_root": 18, "read_only_rootfs": 16},
                   ["SOC2-CC6.1", "ISO27001-A.14.2", "NIST-CM-7", "CIS-Docker-5.1"], ts),
        _sim_item("docker", "image_vulnerabilities", "Container image vulnerability scan",
                   "Trivy scan: 0 critical, 1 high across 12 images",
                   {"scanner": "trivy", "images_scanned": 12, "critical": 0, "high": 1, "medium": 8},
                   ["SOC2-CC7.1", "ISO27001-A.12.6", "NIST-SI-2", "OWASP-A06"], ts),
    ]


def _gen_kubernetes(ts: datetime) -> list[dict]:
    return [
        _sim_item("kubernetes", "rbac_policies", "Kubernetes RBAC properly configured",
                   "Cluster uses RBAC with 24 roles; no cluster-admin for service accounts",
                   {"rbac_enabled": True, "total_roles": 24, "service_account_cluster_admin": 0},
                   ["SOC2-CC6.3", "ISO27001-A.9.2", "NIST-AC-6"], ts),
        _sim_item("kubernetes", "network_policies", "Network policies restrict pod communication",
                   "All namespaces have default-deny ingress",
                   {"namespaces_with_netpol": 6, "total_namespaces": 6, "default_deny_ingress": True},
                   ["SOC2-CC6.6", "ISO27001-A.13.1", "NIST-SC-7"], ts),
    ]


def _gen_okta(ts: datetime) -> list[dict]:
    return [
        _sim_item("okta", "sso_config", "SSO enabled for all critical applications",
                   "SAML/OIDC SSO configured for 28 applications; 97% use SSO",
                   {"total_apps": 28, "sso_apps": 28, "sso_login_pct": 97.2},
                   ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-2"], ts),
        _sim_item("okta", "mfa_enrollment", "MFA enrollment at 99.1%",
                   "342/345 active users enrolled in MFA",
                   {"total_users": 345, "mfa_enrolled": 342, "enrollment_pct": 99.1},
                   ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-2", "HIPAA-164.312(d)"], ts),
    ]


def _gen_google_workspace(ts: datetime) -> list[dict]:
    return [
        _sim_item("google_workspace", "admin_policies", "Google Workspace security policies",
                   "2-step verification enforced, session length 12hr",
                   {"two_step_enforcement": "enforced", "session_length_hours": 12, "less_secure_apps_blocked": True},
                   ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-5"], ts),
    ]


def _gen_slack(ts: datetime) -> list[dict]:
    return [
        _sim_item("slack", "dlp_settings", "Slack DLP rules configured",
                   "12 DLP rules active covering PII, credentials, financial data",
                   {"dlp_rules_active": 12, "action_on_match": "block_and_notify", "detections_30d": 23},
                   ["SOC2-CC6.7", "ISO27001-A.8.2", "NIST-SC-7", "GDPR-Art32"], ts),
        _sim_item("slack", "retention_policies", "Message retention policy enforced",
                   "90-day retention for all channels",
                   {"retention_days": 90, "compliance_export": True},
                   ["SOC2-CC7.4", "ISO27001-A.12.4", "NIST-AU-11", "HIPAA-164.530(j)"], ts),
    ]


def _gen_datadog(ts: datetime) -> list[dict]:
    return [
        _sim_item("datadog", "monitors_config", "Critical monitors configured",
                   "47 monitors active; all P1 services covered",
                   {"total_monitors": 47, "p1_services_monitored": 8, "p1_services_total": 8},
                   ["SOC2-CC7.2", "ISO27001-A.12.1", "NIST-SI-4"], ts),
        _sim_item("datadog", "slo_definitions", "SLO targets defined for critical services",
                   "8 SLOs defined; 99.9% availability target",
                   {"total_slos": 8, "target_availability": 99.9, "current_availability": 99.97},
                   ["SOC2-CC7.1", "ISO27001-A.17.1", "NIST-CP-2"], ts),
    ]


# ---------------------------------------------------------------------------
# Helper: persist evidence results to DB
# ---------------------------------------------------------------------------

def _persist_evidence(
    db: Session,
    connector_db: EvidenceConnectorDB,
    evidence_dicts: list[dict],
) -> list[dict]:
    """Persist evidence items to DB and return serialized list."""
    persisted = []
    now = datetime.now(timezone.utc)

    for ev in evidence_dicts:
        controls_json = json.dumps(ev.get("mapped_controls", []))
        content_json = json.dumps(ev.get("raw_data", {}))

        item = EvidenceItemDB(
            connector_id=connector_db.id,
            control_id=ev.get("mapped_controls", [None])[0] if ev.get("mapped_controls") else None,
            framework=ev.get("framework", ""),
            evidence_type=ev.get("evidence_type", "unknown"),
            title=ev.get("title", ""),
            description=ev.get("description", ""),
            content=content_json,
            source=ev.get("source", ""),
            status="collected",
            collected_at=now,
            mapped_controls=controls_json,
        )
        db.add(item)
        db.flush()

        persisted.append({
            "id": str(item.id),
            "connector": connector_db.name,
            "evidence_type": item.evidence_type,
            "title": item.title,
            "description": item.description,
            "status": item.status,
            "collected_at": item.collected_at.isoformat(),
            "raw_data": ev.get("raw_data", {}),
            "mapped_controls": ev.get("mapped_controls", []),
            "source": item.source,
        })

    connector_db.last_collected_at = now
    db.commit()

    return persisted


def _serialize_evidence_item(item: EvidenceItemDB, connector_name: str = "") -> dict:
    """Convert DB evidence item to API response dict."""
    try:
        raw_data = json.loads(item.content) if item.content else {}
    except (json.JSONDecodeError, TypeError):
        raw_data = {}
    try:
        controls = json.loads(item.mapped_controls) if item.mapped_controls else []
    except (json.JSONDecodeError, TypeError):
        controls = []

    return {
        "id": str(item.id),
        "connector": connector_name or str(item.connector_id),
        "evidence_type": item.evidence_type,
        "title": item.title,
        "description": item.description or "",
        "status": item.status,
        "collected_at": item.collected_at.isoformat() if item.collected_at else "",
        "raw_data": raw_data,
        "mapped_controls": controls,
        "source": item.source or "",
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/connectors")
def list_connectors(
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """List all available integration connectors with connection status from DB."""
    # Get connected connectors from DB
    db_connectors = db.query(EvidenceConnectorDB).all()
    connected_map = {c.name: c for c in db_connectors}

    connectors = []
    for key, info in CONNECTORS.items():
        c = info.model_dump()
        db_conn = connected_map.get(key)
        if db_conn and db_conn.status == "connected":
            c["status"] = ConnectorStatus.CONNECTED.value
            c["last_sync"] = db_conn.last_collected_at.isoformat() if db_conn.last_collected_at else None
        connectors.append(c)
    return {
        "total": len(connectors),
        "connectors": connectors,
    }


@router.post("/connect")
def connect_integration(
    req: ConnectRequest,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Connect an integration connector. For real connectors (aws, github, rest),
    tests the connection first. Persists config to DB."""
    name = req.connector_name.lower()
    if name not in CONNECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {req.connector_name}")

    connector_type = (req.connector_type or name).lower()
    now = datetime.now(timezone.utc)

    # For real connectors, test the connection first
    test_result = None
    if connector_type in REAL_CONNECTOR_TYPES:
        try:
            from src.evidence.connectors import get_connector
            real_connector = get_connector(connector_type, req.credentials)
            test_result = real_connector.test_connection()
            if not test_result.get("ok"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Connection test failed: {test_result.get('message', 'unknown error')}",
                )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Connection test error: {exc}")

    # Persist or update connector in DB
    existing = db.query(EvidenceConnectorDB).filter(
        EvidenceConnectorDB.name == name
    ).first()

    config_json = json.dumps({k: v for k, v in req.credentials.items()})

    if existing:
        existing.config_encrypted = config_json
        existing.status = "connected"
        existing.connector_type = connector_type
        existing.updated_at = now
        db.commit()
    else:
        new_conn = EvidenceConnectorDB(
            name=name,
            connector_type=connector_type,
            config_encrypted=config_json,
            status="connected",
            created_by=auth.identity,
            org_id=str(auth.org_id) if auth.org_id else None,
        )
        db.add(new_conn)
        db.commit()

    return {
        "status": "connected",
        "connector": name,
        "connector_type": connector_type,
        "connected_at": now.isoformat(),
        "real_connector": connector_type in REAL_CONNECTOR_TYPES,
        "test_result": test_result,
        "message": f"Successfully connected to {CONNECTORS[name].description}",
    }


@router.post("/test-connection")
def test_connection(
    req: TestConnectionRequest,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Test an existing connector's connection without collecting evidence."""
    name = req.connector_name.lower()

    connector_db = db.query(EvidenceConnectorDB).filter(
        EvidenceConnectorDB.name == name
    ).first()
    if not connector_db:
        raise HTTPException(status_code=404, detail=f"Connector '{name}' not found. Connect it first.")

    connector_type = connector_db.connector_type
    if connector_type not in REAL_CONNECTOR_TYPES:
        return {
            "connector": name,
            "ok": True,
            "message": f"Simulated connector '{name}' is always available",
            "real_connector": False,
        }

    try:
        config = json.loads(connector_db.config_encrypted) if connector_db.config_encrypted else {}
    except json.JSONDecodeError:
        config = {}

    try:
        from src.evidence.connectors import get_connector
        real_connector = get_connector(connector_type, config)
        result = real_connector.test_connection()
        return {
            "connector": name,
            "real_connector": True,
            **result,
        }
    except Exception as exc:
        return {
            "connector": name,
            "real_connector": True,
            "ok": False,
            "message": str(exc),
        }


@router.post("/collect")
def collect_evidence(
    req: CollectRequest,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Trigger evidence collection. Uses real API calls for aws/github/rest connectors,
    simulated data for others. All results persisted to DB."""
    name = req.connector_name.lower()
    if name not in CONNECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {req.connector_name}")

    # Get or create connector DB record
    connector_db = db.query(EvidenceConnectorDB).filter(
        EvidenceConnectorDB.name == name
    ).first()

    if not connector_db:
        raise HTTPException(
            status_code=400,
            detail=f"Connector '{name}' is not connected. Call POST /v1/evidence/connect first.",
        )

    connector_type = connector_db.connector_type
    evidence_dicts: list[dict] = []

    if connector_type in REAL_CONNECTOR_TYPES:
        # Real connector — make actual API calls
        try:
            config = json.loads(connector_db.config_encrypted) if connector_db.config_encrypted else {}
        except json.JSONDecodeError:
            config = {}

        try:
            from src.evidence.connectors import get_connector
            real_connector = get_connector(connector_type, config)
            results = real_connector.collect_evidence()
            evidence_dicts = [r.to_dict() for r in results]
        except Exception as exc:
            logger.error("Real connector %s failed: %s", name, exc)
            raise HTTPException(
                status_code=500,
                detail=f"Evidence collection failed: {exc}",
            )
    else:
        # Simulated connector
        evidence_dicts = _generate_simulated_evidence(name)

    # Persist all evidence to DB
    persisted = _persist_evidence(db, connector_db, evidence_dicts)

    return {
        "connector": name,
        "connector_type": connector_type,
        "real_connector": connector_type in REAL_CONNECTOR_TYPES,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "evidence_count": len(persisted),
        "evidence": persisted,
    }


@router.get("")
def list_evidence(
    connector: Optional[str] = Query(None, description="Filter by connector name"),
    control_id: Optional[str] = Query(None, description="Filter by mapped control ID"),
    status: Optional[str] = Query(None, description="Filter by evidence status"),
    days: Optional[int] = Query(None, description="Filter to evidence collected in the last N days"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """List all collected evidence from DB with filters."""
    query = db.query(EvidenceItemDB).join(EvidenceConnectorDB)

    if connector:
        query = query.filter(EvidenceConnectorDB.name == connector.lower())
    if control_id:
        query = query.filter(EvidenceItemDB.mapped_controls.contains(control_id))
    if status:
        query = query.filter(EvidenceItemDB.status == status)
    if days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(EvidenceItemDB.collected_at >= cutoff)

    total = query.count()
    items = (
        query.order_by(EvidenceItemDB.collected_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    # Build connector name lookup
    connector_ids = {i.connector_id for i in items}
    connectors_db = db.query(EvidenceConnectorDB).filter(
        EvidenceConnectorDB.id.in_(connector_ids)
    ).all() if connector_ids else []
    name_map = {c.id: c.name for c in connectors_db}

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit if total else 0,
        "evidence": [_serialize_evidence_item(i, name_map.get(i.connector_id, "")) for i in items],
    }


@router.get("/coverage")
def evidence_coverage(
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Evidence coverage report from DB: which controls have evidence, which are missing."""
    all_items = db.query(EvidenceItemDB).all()

    # Build control -> evidence mapping from DB records
    control_evidence: dict[str, list] = {}
    for item in all_items:
        try:
            controls = json.loads(item.mapped_controls) if item.mapped_controls else []
        except (json.JSONDecodeError, TypeError):
            controls = []
        for cid in controls:
            control_evidence.setdefault(cid, []).append(item)

    details = []
    by_framework: dict[str, dict] = {}

    for ctrl in COMPLIANCE_CONTROLS:
        cid = ctrl["id"]
        fw = ctrl["framework"]
        ev_list = control_evidence.get(cid, [])
        has_ev = len(ev_list) > 0
        last_at = None
        if ev_list:
            dates = [e.collected_at for e in ev_list if e.collected_at]
            last_at = max(dates).isoformat() if dates else None

        details.append({
            "control_id": cid,
            "control_name": ctrl["name"],
            "framework": fw,
            "has_evidence": has_ev,
            "evidence_count": len(ev_list),
            "last_evidence_at": last_at,
        })

        fw_stats = by_framework.setdefault(fw, {"total": 0, "covered": 0, "missing": 0})
        fw_stats["total"] += 1
        if has_ev:
            fw_stats["covered"] += 1
        else:
            fw_stats["missing"] += 1

    for fw, stats in by_framework.items():
        stats["coverage_pct"] = round((stats["covered"] / stats["total"]) * 100, 1) if stats["total"] else 0.0

    total = len(COMPLIANCE_CONTROLS)
    covered = sum(1 for d in details if d["has_evidence"])

    return {
        "total_controls": total,
        "covered_controls": covered,
        "missing_controls": total - covered,
        "coverage_pct": round((covered / total) * 100, 1) if total else 0.0,
        "by_framework": by_framework,
        "details": details,
    }


@router.get("/timeline")
def evidence_timeline(
    limit: int = Query(100, ge=1, le=500),
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Evidence collection timeline from DB."""
    items = (
        db.query(EvidenceItemDB)
        .join(EvidenceConnectorDB)
        .order_by(EvidenceItemDB.collected_at.desc())
        .limit(limit)
        .all()
    )

    connector_ids = {i.connector_id for i in items}
    connectors_db = db.query(EvidenceConnectorDB).filter(
        EvidenceConnectorDB.id.in_(connector_ids)
    ).all() if connector_ids else []
    name_map = {c.id: c.name for c in connectors_db}

    entries = [
        {
            "timestamp": i.collected_at.isoformat() if i.collected_at else "",
            "connector": name_map.get(i.connector_id, ""),
            "action": "collected",
            "evidence_count": 1,
            "status": i.status,
            "details": i.title,
        }
        for i in items
    ]

    total = db.query(EvidenceItemDB).count()

    return {
        "total": total,
        "entries": entries,
    }


@router.get("/{evidence_id}")
def get_evidence(
    evidence_id: str,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Get detailed evidence item by ID from DB."""
    try:
        eid = int(evidence_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Evidence not found")

    item = db.query(EvidenceItemDB).filter(EvidenceItemDB.id == eid).first()
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")

    connector_db = db.query(EvidenceConnectorDB).filter(
        EvidenceConnectorDB.id == item.connector_id
    ).first()
    connector_name = connector_db.name if connector_db else ""

    return _serialize_evidence_item(item, connector_name)


@router.post("/map")
def map_evidence(
    req: MapRequest,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Map evidence to compliance controls (persisted to DB)."""
    try:
        eid = int(req.evidence_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Evidence not found")

    item = db.query(EvidenceItemDB).filter(EvidenceItemDB.id == eid).first()
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")

    valid_ids = {c["id"] for c in COMPLIANCE_CONTROLS}
    invalid = [cid for cid in req.control_ids if cid not in valid_ids]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown control IDs: {invalid}")

    try:
        existing = set(json.loads(item.mapped_controls)) if item.mapped_controls else set()
    except (json.JSONDecodeError, TypeError):
        existing = set()

    added = [cid for cid in req.control_ids if cid not in existing]
    new_controls = list(existing | set(req.control_ids))
    item.mapped_controls = json.dumps(new_controls)
    db.commit()

    return {
        "evidence_id": req.evidence_id,
        "mapped_controls": new_controls,
        "added": added,
        "total_mappings": len(new_controls),
    }


@router.post("/schedule")
def schedule_collection(
    req: ScheduleRequest,
    auth: AuthContext = Depends(require_scope("audit")),
    db: Session = Depends(get_db),
) -> dict:
    """Schedule automatic evidence collection for a connector (persisted to DB)."""
    name = req.connector_name.lower()
    if name not in CONNECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {req.connector_name}")

    connector_db = db.query(EvidenceConnectorDB).filter(
        EvidenceConnectorDB.name == name
    ).first()
    if not connector_db:
        raise HTTPException(
            status_code=400,
            detail=f"Connector '{name}' is not connected. Connect it first.",
        )

    now = datetime.now(timezone.utc)
    freq_cron = {
        CollectionFrequency.HOURLY: "0 * * * *",
        CollectionFrequency.DAILY: "0 0 * * *",
        CollectionFrequency.WEEKLY: "0 0 * * 0",
    }
    freq_deltas = {
        CollectionFrequency.HOURLY: timedelta(hours=1),
        CollectionFrequency.DAILY: timedelta(days=1),
        CollectionFrequency.WEEKLY: timedelta(weeks=1),
    }
    next_run = now + freq_deltas[req.frequency]

    schedule = EvidenceScheduleDB(
        connector_id=connector_db.id,
        cron_expression=freq_cron[req.frequency],
        enabled=True,
        next_run_at=next_run,
    )
    db.add(schedule)
    db.commit()

    return {
        "id": str(schedule.id),
        "connector": name,
        "frequency": req.frequency.value,
        "cron_expression": schedule.cron_expression,
        "next_run": next_run.isoformat(),
        "created_at": schedule.created_at.isoformat(),
    }
