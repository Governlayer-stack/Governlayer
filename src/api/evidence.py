"""Evidence Auto-Collection API — continuous compliance evidence gathering.

Closes the gap with Vanta (300+ integrations) by providing the framework
and key connectors for automated evidence collection, mapping to compliance
controls, and coverage reporting.
"""

import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.security.api_key_auth import AuthContext, require_scope

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
        description="Connector-specific credentials (stored in memory, simulated)",
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


class ScheduleInfo(BaseModel):
    id: str
    connector: str
    frequency: str
    next_run: str
    created_at: str


class CoverageEntry(BaseModel):
    control_id: str
    control_name: str
    framework: str
    has_evidence: bool
    evidence_count: int
    last_evidence_at: Optional[str] = None


class CoverageReport(BaseModel):
    total_controls: int
    covered_controls: int
    missing_controls: int
    coverage_pct: float
    by_framework: dict[str, dict]
    details: list[CoverageEntry]


class TimelineEntry(BaseModel):
    timestamp: str
    connector: str
    action: str
    evidence_count: int
    status: str
    details: Optional[str] = None


# ---------------------------------------------------------------------------
# In-Memory Storage
# ---------------------------------------------------------------------------

_connected: dict[str, dict] = {}
_evidence: dict[str, dict] = {}
_schedules: dict[str, dict] = {}
_timeline: list[dict] = []


# ---------------------------------------------------------------------------
# Connector Registry
# ---------------------------------------------------------------------------

CONNECTORS: dict[str, ConnectorInfo] = {
    "aws": ConnectorInfo(
        name="aws",
        category="Cloud Infrastructure",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["iam_policies", "cloudtrail_status", "s3_encryption", "vpc_flow_logs", "guardduty_findings"],
        description="Amazon Web Services — IAM, CloudTrail, S3, VPC, GuardDuty",
    ),
    "github": ConnectorInfo(
        name="github",
        category="Source Control",
        status=ConnectorStatus.AVAILABLE,
        evidence_types=["branch_protection", "secret_scanning", "dependency_review", "code_scanning", "audit_log"],
        description="GitHub — repo security, branch rules, secret scanning, dependency review",
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


# ---------------------------------------------------------------------------
# Simulated Evidence Generators
# ---------------------------------------------------------------------------

def _generate_evidence(connector_name: str) -> list[dict]:
    """Generate realistic evidence items for a given connector."""
    now = datetime.utcnow()
    generators = {
        "aws": _gen_aws,
        "github": _gen_github,
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


def _make_item(connector: str, etype: str, title: str, desc: str,
               raw: dict, controls: list[str], ts: datetime) -> dict:
    eid = str(uuid.uuid4())
    item = {
        "id": eid,
        "connector": connector,
        "evidence_type": etype,
        "title": title,
        "description": desc,
        "status": EvidenceStatus.COLLECTED.value,
        "collected_at": ts.isoformat(),
        "raw_data": raw,
        "mapped_controls": controls,
        "source": f"{connector}:auto-collect",
    }
    _evidence[eid] = item
    return item


def _gen_aws(ts: datetime) -> list[dict]:
    return [
        _make_item("aws", "iam_policies", "IAM password policy enforced",
                    "AWS account password policy requires 14+ chars, rotation every 90 days, MFA enabled",
                    {"min_length": 14, "require_uppercase": True, "require_lowercase": True,
                     "require_numbers": True, "require_symbols": True, "max_age_days": 90,
                     "mfa_required": True, "reuse_prevention": 24},
                    ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-5"], ts),
        _make_item("aws", "cloudtrail_status", "CloudTrail enabled in all regions",
                    "Multi-region CloudTrail with log file validation and S3 delivery",
                    {"is_multi_region": True, "is_logging": True, "log_file_validation": True,
                     "s3_bucket": "company-cloudtrail-logs", "kms_key_id": "arn:aws:kms:us-east-1:123456789:key/abc-def",
                     "include_global_events": True, "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789:trail/main"},
                    ["SOC2-CC7.2", "ISO27001-A.12.4", "NIST-AU-2", "HIPAA-164.312(b)"], ts),
        _make_item("aws", "s3_encryption", "S3 buckets encrypted at rest",
                    "All 23 S3 buckets use AES-256 or AWS KMS server-side encryption",
                    {"total_buckets": 23, "encrypted_buckets": 23, "encryption_types": {"AES256": 8, "aws:kms": 15},
                     "public_buckets": 0, "versioning_enabled": 21},
                    ["SOC2-CC6.7", "ISO27001-A.10.1", "NIST-SC-28", "GDPR-Art32"], ts),
        _make_item("aws", "vpc_flow_logs", "VPC flow logs enabled",
                    "All 4 VPCs have flow logs enabled, delivering to CloudWatch Logs",
                    {"total_vpcs": 4, "vpcs_with_flow_logs": 4, "log_destination": "cloudwatch",
                     "traffic_type": "ALL", "retention_days": 365},
                    ["SOC2-CC7.2", "ISO27001-A.13.1", "NIST-SI-4"], ts),
    ]


def _gen_github(ts: datetime) -> list[dict]:
    return [
        _make_item("github", "branch_protection", "Branch protection on main branches",
                    "12/12 production repos have branch protection: required reviews, status checks, no force push",
                    {"total_repos": 12, "protected_repos": 12, "require_reviews": True,
                     "required_reviewers": 2, "require_status_checks": True,
                     "enforce_admins": True, "no_force_push": True, "require_signed_commits": True},
                    ["SOC2-CC8.1", "ISO27001-A.14.2", "NIST-CM-3"], ts),
        _make_item("github", "secret_scanning", "Secret scanning active with no open alerts",
                    "GitHub Advanced Security secret scanning enabled; 0 open alerts, 3 resolved in last 30 days",
                    {"enabled": True, "push_protection": True, "open_alerts": 0,
                     "resolved_30d": 3, "patterns_monitored": 147, "custom_patterns": 5},
                    ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-5", "OWASP-A07"], ts),
        _make_item("github", "dependency_review", "Dependency vulnerabilities managed",
                    "Dependabot enabled; 0 critical, 2 high vulns with PRs in review",
                    {"dependabot_enabled": True, "critical_vulns": 0, "high_vulns": 2,
                     "medium_vulns": 7, "low_vulns": 12, "auto_merge_patches": True,
                     "prs_open": 2, "avg_remediation_days": 3.2},
                    ["SOC2-CC7.1", "ISO27001-A.12.6", "NIST-SI-2", "OWASP-A06"], ts),
    ]


def _gen_postgresql(ts: datetime) -> list[dict]:
    return [
        _make_item("postgresql", "ssl_config", "SSL/TLS enforced for all connections",
                    "PostgreSQL configured with ssl=on, minimum TLS 1.2, client cert verification optional",
                    {"ssl_enabled": True, "ssl_min_version": "TLSv1.2", "ssl_cert": "/etc/ssl/server.crt",
                     "ssl_key": "/etc/ssl/server.key", "ssl_ca": "/etc/ssl/ca.crt",
                     "connections_ssl": 148, "connections_plain": 0},
                    ["SOC2-CC6.7", "ISO27001-A.13.1", "NIST-SC-8", "HIPAA-164.312(e)"], ts),
        _make_item("postgresql", "password_policy", "Strong password authentication policy",
                    "scram-sha-256 auth method, password_encryption enabled, no trust/md5 entries in pg_hba.conf",
                    {"auth_method": "scram-sha-256", "password_encryption": "scram-sha-256",
                     "pg_hba_trust_entries": 0, "pg_hba_md5_entries": 0,
                     "connection_limit_per_user": 50, "idle_session_timeout": "10min"},
                    ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-5"], ts),
        _make_item("postgresql", "audit_logging", "Database audit logging active",
                    "pgaudit extension enabled, logging DDL, DML on sensitive tables, log_connections=on",
                    {"pgaudit_enabled": True, "log_statement": "ddl", "log_connections": True,
                     "log_disconnections": True, "log_duration": True,
                     "pgaudit_roles": ["audit_reader"], "log_destination": "csvlog",
                     "log_retention_days": 90},
                    ["SOC2-CC7.2", "ISO27001-A.12.4", "NIST-AU-2", "HIPAA-164.312(b)"], ts),
        _make_item("postgresql", "user_privileges", "Least-privilege database roles",
                    "14 database roles reviewed; no excess superuser accounts, app uses read-only where possible",
                    {"total_roles": 14, "superusers": 1, "app_roles_readonly": 8,
                     "app_roles_readwrite": 4, "admin_roles": 1, "last_privilege_review": (ts - timedelta(days=12)).isoformat(),
                     "orphaned_roles": 0},
                    ["SOC2-CC6.3", "ISO27001-A.9.2", "NIST-AC-6"], ts),
    ]


def _gen_docker(ts: datetime) -> list[dict]:
    return [
        _make_item("docker", "no_root_containers", "Containers running as non-root",
                    "18/18 production containers run as non-root user with read-only root filesystem",
                    {"total_containers": 18, "non_root": 18, "read_only_rootfs": 16,
                     "no_new_privileges": 18, "seccomp_profile": "default",
                     "apparmor_profile": "docker-default"},
                    ["SOC2-CC6.1", "ISO27001-A.14.2", "NIST-CM-7", "CIS-Docker-5.1"], ts),
        _make_item("docker", "image_vulnerabilities", "Container image vulnerability scan",
                    "Trivy scan: 0 critical, 1 high across 12 images; all base images < 30 days old",
                    {"scanner": "trivy", "images_scanned": 12, "critical": 0, "high": 1,
                     "medium": 8, "low": 23, "base_image_max_age_days": 28,
                     "signed_images": 12, "sbom_generated": True},
                    ["SOC2-CC7.1", "ISO27001-A.12.6", "NIST-SI-2", "OWASP-A06"], ts),
        _make_item("docker", "resource_limits", "Resource limits set on all containers",
                    "CPU and memory limits enforced; no container can consume unlimited host resources",
                    {"containers_with_cpu_limit": 18, "containers_with_mem_limit": 18,
                     "containers_total": 18, "avg_cpu_limit": "500m", "avg_mem_limit": "512Mi",
                     "oom_kills_30d": 0},
                    ["SOC2-CC7.1", "ISO27001-A.12.1", "NIST-SC-6"], ts),
    ]


def _gen_kubernetes(ts: datetime) -> list[dict]:
    return [
        _make_item("kubernetes", "rbac_policies", "Kubernetes RBAC properly configured",
                    "Cluster uses RBAC with 24 roles; no cluster-admin bindings for service accounts",
                    {"rbac_enabled": True, "total_roles": 24, "cluster_roles": 8,
                     "service_account_cluster_admin": 0, "default_sa_automount": False,
                     "namespaces_with_resource_quotas": 6, "total_namespaces": 6},
                    ["SOC2-CC6.3", "ISO27001-A.9.2", "NIST-AC-6"], ts),
        _make_item("kubernetes", "network_policies", "Network policies restrict pod communication",
                    "All production namespaces have default-deny ingress NetworkPolicy",
                    {"namespaces_with_netpol": 6, "total_namespaces": 6,
                     "default_deny_ingress": True, "default_deny_egress": False,
                     "total_network_policies": 14},
                    ["SOC2-CC6.6", "ISO27001-A.13.1", "NIST-SC-7"], ts),
        _make_item("kubernetes", "pod_security", "Pod security standards enforced",
                    "Restricted pod security standard enforced at namespace level via admission controller",
                    {"pod_security_standard": "restricted", "enforcement_mode": "enforce",
                     "privileged_pods": 0, "host_network_pods": 0, "host_pid_pods": 0,
                     "admission_controller": "PodSecurity"},
                    ["SOC2-CC6.1", "ISO27001-A.14.2", "NIST-CM-7", "CIS-K8s-5.2"], ts),
    ]


def _gen_okta(ts: datetime) -> list[dict]:
    return [
        _make_item("okta", "sso_config", "SSO enabled for all critical applications",
                    "SAML/OIDC SSO configured for 28 applications; 97% of logins use SSO",
                    {"total_apps": 28, "sso_apps": 28, "sso_login_pct": 97.2,
                     "protocols": {"SAML": 18, "OIDC": 10}, "password_only_logins_30d": 42,
                     "total_logins_30d": 1523},
                    ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-2"], ts),
        _make_item("okta", "mfa_enrollment", "MFA enrollment at 99.1%",
                    "342/345 active users enrolled in MFA; 3 users in grace period expiring in 48hrs",
                    {"total_users": 345, "mfa_enrolled": 342, "enrollment_pct": 99.1,
                     "mfa_methods": {"okta_verify": 310, "webauthn": 180, "sms": 45},
                     "grace_period_users": 3, "grace_expires_hours": 48},
                    ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-2", "HIPAA-164.312(d)"], ts),
    ]


def _gen_google_workspace(ts: datetime) -> list[dict]:
    return [
        _make_item("google_workspace", "admin_policies", "Google Workspace security policies",
                    "2-step verification enforced, session length 12hr, less secure apps blocked",
                    {"two_step_enforcement": "enforced", "session_length_hours": 12,
                     "less_secure_apps_blocked": True, "password_min_length": 12,
                     "password_reuse_limit": 5, "admin_accounts": 4, "super_admins": 2},
                    ["SOC2-CC6.1", "ISO27001-A.9.4", "NIST-IA-5"], ts),
        _make_item("google_workspace", "drive_sharing", "Drive external sharing restricted",
                    "External sharing requires allowlisted domains; link sharing defaults to org-only",
                    {"external_sharing": "allowlisted_domains", "allowlisted_domains": 3,
                     "default_link_sharing": "organization", "dlp_rules_active": 8,
                     "files_shared_externally_30d": 47, "drive_audit_enabled": True},
                    ["SOC2-CC6.6", "ISO27001-A.8.2", "NIST-AC-3", "GDPR-Art32"], ts),
    ]


def _gen_slack(ts: datetime) -> list[dict]:
    return [
        _make_item("slack", "dlp_settings", "Slack DLP rules configured",
                    "12 DLP rules active covering PII, credentials, financial data patterns",
                    {"dlp_rules_active": 12, "categories": ["PII", "credentials", "financial", "health"],
                     "action_on_match": "block_and_notify", "detections_30d": 23,
                     "false_positive_rate": 0.04, "custom_patterns": 5},
                    ["SOC2-CC6.7", "ISO27001-A.8.2", "NIST-SC-7", "GDPR-Art32"], ts),
        _make_item("slack", "retention_policies", "Message retention policy enforced",
                    "90-day retention for all channels; compliance exports enabled for legal hold",
                    {"retention_days": 90, "file_retention_days": 90, "compliance_export": True,
                     "legal_hold_active": False, "ediscovery_enabled": True,
                     "channels_with_custom_retention": 3},
                    ["SOC2-CC7.4", "ISO27001-A.12.4", "NIST-AU-11", "HIPAA-164.530(j)"], ts),
    ]


def _gen_datadog(ts: datetime) -> list[dict]:
    return [
        _make_item("datadog", "monitors_config", "Critical monitors configured",
                    "47 monitors active; all P1 services have latency, error rate, and throughput monitors",
                    {"total_monitors": 47, "p1_services_monitored": 8, "p1_services_total": 8,
                     "monitor_types": {"metric": 28, "log": 9, "apm": 6, "synthetics": 4},
                     "alerts_30d": 12, "mtta_minutes": 4.2, "mttr_minutes": 23.8},
                    ["SOC2-CC7.2", "ISO27001-A.12.1", "NIST-SI-4"], ts),
        _make_item("datadog", "slo_definitions", "SLO targets defined for critical services",
                    "8 SLOs defined; all P1 services have 99.9% availability target, error budget at 62%",
                    {"total_slos": 8, "target_availability": 99.9, "current_availability": 99.97,
                     "error_budget_remaining_pct": 62.3, "slo_breaches_90d": 0,
                     "burn_rate_alerts": True},
                    ["SOC2-CC7.1", "ISO27001-A.17.1", "NIST-CP-2"], ts),
    ]


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
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/connectors")
def list_connectors(
    auth: AuthContext = Depends(require_scope("audit")),
) -> dict:
    """List all available integration connectors with connection status."""
    connectors = []
    for key, info in CONNECTORS.items():
        c = info.model_dump()
        if key in _connected:
            c["status"] = ConnectorStatus.CONNECTED.value
            c["last_sync"] = _connected[key].get("connected_at")
        connectors.append(c)
    return {
        "total": len(connectors),
        "connectors": connectors,
    }


@router.post("/connect")
def connect_integration(
    req: ConnectRequest,
    auth: AuthContext = Depends(require_scope("audit")),
) -> dict:
    """Connect an integration connector (credentials stored in memory, simulated)."""
    name = req.connector_name.lower()
    if name not in CONNECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {req.connector_name}")

    now = datetime.utcnow().isoformat()
    _connected[name] = {
        "connector": name,
        "connected_at": now,
        "connected_by": auth.identity,
        "credential_keys": list(req.credentials.keys()),
    }

    _timeline.append({
        "timestamp": now,
        "connector": name,
        "action": "connected",
        "evidence_count": 0,
        "status": "success",
        "details": f"Integration connected by {auth.identity}",
    })

    return {
        "status": "connected",
        "connector": name,
        "connected_at": now,
        "message": f"Successfully connected to {CONNECTORS[name].description}",
    }


@router.post("/collect")
def collect_evidence(
    req: CollectRequest,
    auth: AuthContext = Depends(require_scope("audit")),
) -> dict:
    """Trigger evidence collection for a connector. Returns simulated evidence items."""
    name = req.connector_name.lower()
    if name not in CONNECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {req.connector_name}")
    if name not in _connected:
        raise HTTPException(status_code=400, detail=f"Connector '{name}' is not connected. Call POST /v1/evidence/connect first.")

    items = _generate_evidence(name)
    now = datetime.utcnow().isoformat()

    _connected[name]["last_sync"] = now

    _timeline.append({
        "timestamp": now,
        "connector": name,
        "action": "collected",
        "evidence_count": len(items),
        "status": "success",
        "details": f"Collected {len(items)} evidence items",
    })

    return {
        "connector": name,
        "collected_at": now,
        "evidence_count": len(items),
        "evidence": items,
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
) -> dict:
    """List all collected evidence with filters."""
    items = list(_evidence.values())

    if connector:
        items = [e for e in items if e["connector"] == connector.lower()]
    if control_id:
        items = [e for e in items if control_id in e["mapped_controls"]]
    if status:
        items = [e for e in items if e["status"] == status]
    if days:
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        items = [e for e in items if e["collected_at"] >= cutoff]

    # Sort by collected_at descending
    items.sort(key=lambda x: x["collected_at"], reverse=True)

    total = len(items)
    start = (page - 1) * limit
    paged = items[start : start + limit]

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit if total else 0,
        "evidence": paged,
    }


@router.get("/coverage")
def evidence_coverage(
    auth: AuthContext = Depends(require_scope("audit")),
) -> dict:
    """Evidence coverage report: which controls have evidence, which are missing."""
    # Build control -> evidence mapping
    control_evidence: dict[str, list[dict]] = {}
    for item in _evidence.values():
        for cid in item["mapped_controls"]:
            control_evidence.setdefault(cid, []).append(item)

    details = []
    by_framework: dict[str, dict] = {}

    for ctrl in COMPLIANCE_CONTROLS:
        cid = ctrl["id"]
        fw = ctrl["framework"]
        ev_list = control_evidence.get(cid, [])
        has_ev = len(ev_list) > 0
        last_at = max((e["collected_at"] for e in ev_list), default=None) if ev_list else None

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

    # Calculate percentages
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
) -> dict:
    """Evidence collection timeline for audit trail."""
    entries = sorted(_timeline, key=lambda x: x["timestamp"], reverse=True)[:limit]
    return {
        "total": len(_timeline),
        "entries": entries,
    }


@router.get("/{evidence_id}")
def get_evidence(
    evidence_id: str,
    auth: AuthContext = Depends(require_scope("audit")),
) -> dict:
    """Get detailed evidence item by ID."""
    item = _evidence.get(evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return item


@router.post("/map")
def map_evidence(
    req: MapRequest,
    auth: AuthContext = Depends(require_scope("audit")),
) -> dict:
    """Map evidence to compliance controls."""
    item = _evidence.get(req.evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")

    valid_ids = {c["id"] for c in COMPLIANCE_CONTROLS}
    invalid = [cid for cid in req.control_ids if cid not in valid_ids]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown control IDs: {invalid}")

    existing = set(item["mapped_controls"])
    added = [cid for cid in req.control_ids if cid not in existing]
    item["mapped_controls"] = list(existing | set(req.control_ids))

    _timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "connector": item["connector"],
        "action": "mapped",
        "evidence_count": 1,
        "status": "success",
        "details": f"Mapped {len(added)} controls to evidence {req.evidence_id[:8]}...",
    })

    return {
        "evidence_id": req.evidence_id,
        "mapped_controls": item["mapped_controls"],
        "added": added,
        "total_mappings": len(item["mapped_controls"]),
    }


@router.post("/schedule")
def schedule_collection(
    req: ScheduleRequest,
    auth: AuthContext = Depends(require_scope("audit")),
) -> dict:
    """Schedule automatic evidence collection for a connector."""
    name = req.connector_name.lower()
    if name not in CONNECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {req.connector_name}")

    now = datetime.utcnow()
    freq_deltas = {
        CollectionFrequency.HOURLY: timedelta(hours=1),
        CollectionFrequency.DAILY: timedelta(days=1),
        CollectionFrequency.WEEKLY: timedelta(weeks=1),
    }
    next_run = now + freq_deltas[req.frequency]

    schedule_id = str(uuid.uuid4())
    schedule = {
        "id": schedule_id,
        "connector": name,
        "frequency": req.frequency.value,
        "next_run": next_run.isoformat(),
        "created_at": now.isoformat(),
        "created_by": auth.identity,
    }
    _schedules[schedule_id] = schedule

    _timeline.append({
        "timestamp": now.isoformat(),
        "connector": name,
        "action": "scheduled",
        "evidence_count": 0,
        "status": "success",
        "details": f"Scheduled {req.frequency.value} collection",
    })

    return schedule
