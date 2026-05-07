"""Asset Inventory API — catalog systems, databases, SaaS tools, and infrastructure.

Enterprise compliance requires a complete inventory of all assets. Assets can be
auto-discovered from integrations (AWS, GitHub, GCP, Okta, Datadog) or manually added.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, EmailStr

from src.security.auth import verify_token

router = APIRouter(prefix="/v1/assets", tags=["Asset Inventory"])


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AssetType(str, Enum):
    server = "server"
    database = "database"
    saas_app = "saas_app"
    api = "api"
    container = "container"
    storage = "storage"
    network = "network"
    endpoint = "endpoint"
    ai_model = "ai_model"


class Environment(str, Enum):
    production = "production"
    staging = "staging"
    development = "development"


class DataClassification(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class DiscoverySource(str, Enum):
    manual = "manual"
    github = "github"
    aws = "aws"
    gcp = "gcp"
    okta = "okta"
    datadog = "datadog"


class AssetStatus(str, Enum):
    active = "active"
    decommissioned = "decommissioned"
    under_review = "under_review"


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    type: AssetType
    owner: Optional[str] = Field(None, max_length=256)
    department: Optional[str] = Field(None, max_length=128)
    environment: Environment = Environment.production
    data_classification: Optional[DataClassification] = None
    description: Optional[str] = Field(None, max_length=2048)
    tags: list[str] = Field(default_factory=list)
    discovered_from: Optional[DiscoverySource] = DiscoverySource.manual
    compliance_controls: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.medium
    metadata: dict = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    type: Optional[AssetType] = None
    owner: Optional[str] = Field(None, max_length=256)
    department: Optional[str] = Field(None, max_length=128)
    environment: Optional[Environment] = None
    data_classification: Optional[DataClassification] = None
    description: Optional[str] = Field(None, max_length=2048)
    tags: Optional[list[str]] = None
    compliance_controls: Optional[list[str]] = None
    risk_level: Optional[RiskLevel] = None
    status: Optional[AssetStatus] = None
    metadata: Optional[dict] = None


class ControlMapping(BaseModel):
    control_ids: list[str] = Field(..., min_length=1)


class DiscoverRequest(BaseModel):
    source: DiscoverySource


class Asset(BaseModel):
    id: str
    name: str
    type: AssetType
    owner: Optional[str]
    department: Optional[str]
    environment: Environment
    data_classification: Optional[DataClassification]
    description: Optional[str]
    tags: list[str]
    discovered_from: Optional[DiscoverySource]
    status: AssetStatus
    compliance_controls: list[str]
    risk_level: RiskLevel
    created_at: str
    updated_at: str
    last_scanned: Optional[str]
    metadata: dict


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

_assets: dict[str, dict] = {}
_seeded: bool = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_asset(
    name: str,
    asset_type: AssetType,
    owner: Optional[str],
    department: Optional[str],
    environment: Environment,
    data_classification: Optional[DataClassification],
    description: Optional[str],
    tags: list[str],
    discovered_from: Optional[DiscoverySource],
    compliance_controls: list[str],
    risk_level: RiskLevel,
    metadata: Optional[dict] = None,
    status: AssetStatus = AssetStatus.active,
    last_scanned: Optional[str] = None,
) -> dict:
    now = _now_iso()
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": asset_type.value,
        "owner": owner,
        "department": department,
        "environment": environment.value,
        "data_classification": data_classification.value if data_classification else None,
        "description": description,
        "tags": tags,
        "discovered_from": discovered_from.value if discovered_from else None,
        "status": status.value,
        "compliance_controls": compliance_controls,
        "risk_level": risk_level.value,
        "created_at": now,
        "updated_at": now,
        "last_scanned": last_scanned,
        "metadata": metadata or {},
    }


def _seed_demo_assets() -> None:
    """Populate the store with representative demo assets on first access."""
    global _seeded
    if _seeded:
        return
    _seeded = True

    seeds = [
        _make_asset(
            "prod-api-gateway", AssetType.api, "platform@governlayer.ai", "Engineering",
            Environment.production, DataClassification.confidential,
            "Primary API gateway handling all external traffic",
            ["core", "public-facing"], DiscoverySource.aws,
            ["SOC2-CC6.1", "ISO27001-A.13"], RiskLevel.high,
            metadata={"region": "us-east-1", "provider": "AWS API Gateway"},
            last_scanned=_now_iso(),
        ),
        _make_asset(
            "governlayer-postgres", AssetType.database, "dba@governlayer.ai", "Engineering",
            Environment.production, DataClassification.restricted,
            "Primary PostgreSQL database storing audit records and user data",
            ["core", "pii"], DiscoverySource.aws,
            ["SOC2-CC6.1", "GDPR-Art32", "HIPAA-164.312"], RiskLevel.critical,
            metadata={"engine": "PostgreSQL 15", "instance": "db.r6g.xlarge"},
            last_scanned=_now_iso(),
        ),
        _make_asset(
            "redis-cache", AssetType.database, "platform@governlayer.ai", "Engineering",
            Environment.production, DataClassification.internal,
            "Redis cluster for session cache and rate limiting",
            ["cache", "core"], DiscoverySource.aws,
            ["SOC2-CC6.6"], RiskLevel.medium,
            metadata={"engine": "Redis 7", "cluster_mode": True},
        ),
        _make_asset(
            "achonye-orchestrator", AssetType.ai_model, "ml@governlayer.ai", "AI/ML",
            Environment.production, DataClassification.confidential,
            "Multi-LLM orchestration engine routing tasks across 14 models",
            ["ai", "core", "llm"], DiscoverySource.manual,
            ["NIST-AI-600-1", "EU-AI-Act-Art9"], RiskLevel.high,
            metadata={"models": 14, "consensus_strategies": 3},
        ),
        _make_asset(
            "drift-detector", AssetType.ai_model, "ml@governlayer.ai", "AI/ML",
            Environment.production, DataClassification.internal,
            "Behavioral drift detection using sentence-transformer embeddings",
            ["ai", "safety", "monitoring"], DiscoverySource.manual,
            ["NIST-AI-600-1", "ISO42001-6.2"], RiskLevel.medium,
            metadata={"embedding_model": "all-MiniLM-L6-v2"},
        ),
        _make_asset(
            "okta-sso", AssetType.saas_app, "it@governlayer.ai", "IT",
            Environment.production, DataClassification.confidential,
            "Single sign-on and identity provider for all employees",
            ["identity", "sso", "critical"], DiscoverySource.okta,
            ["SOC2-CC6.1", "SOC2-CC6.2", "NIST-AC-2"], RiskLevel.high,
            metadata={"users": 156, "mfa_enforced": True},
            last_scanned=_now_iso(),
        ),
        _make_asset(
            "github-org", AssetType.saas_app, "engineering@governlayer.ai", "Engineering",
            Environment.production, DataClassification.confidential,
            "Source code repository and CI/CD platform",
            ["scm", "ci-cd", "code"], DiscoverySource.github,
            ["SOC2-CC8.1", "ISO27001-A.14"], RiskLevel.high,
            metadata={"repos": 42, "branch_protection": True},
            last_scanned=_now_iso(),
        ),
        _make_asset(
            "datadog-monitoring", AssetType.saas_app, "sre@governlayer.ai", "SRE",
            Environment.production, DataClassification.internal,
            "Observability platform for metrics, logs, and traces",
            ["monitoring", "observability"], DiscoverySource.datadog,
            ["SOC2-CC7.1", "SOC2-CC7.2"], RiskLevel.medium,
            metadata={"hosts_monitored": 38, "log_retention_days": 30},
            last_scanned=_now_iso(),
        ),
        _make_asset(
            "k8s-prod-cluster", AssetType.container, "platform@governlayer.ai", "Engineering",
            Environment.production, DataClassification.confidential,
            "Production Kubernetes cluster running all microservices",
            ["k8s", "core", "orchestration"], DiscoverySource.aws,
            ["SOC2-CC6.1", "CIS-Benchmark-K8s"], RiskLevel.critical,
            metadata={"nodes": 12, "version": "1.29", "provider": "EKS"},
        ),
        _make_asset(
            "s3-audit-logs", AssetType.storage, "security@governlayer.ai", "Security",
            Environment.production, DataClassification.restricted,
            "S3 bucket storing immutable audit log archives",
            ["audit", "compliance", "storage"], DiscoverySource.aws,
            ["SOC2-CC7.2", "GDPR-Art30", "SEC-17a-4"], RiskLevel.high,
            metadata={"bucket": "governlayer-audit-logs", "encryption": "AES-256", "versioning": True},
        ),
        _make_asset(
            "staging-api", AssetType.server, "platform@governlayer.ai", "Engineering",
            Environment.staging, DataClassification.internal,
            "Staging environment API server for pre-production testing",
            ["staging", "test"], DiscoverySource.aws,
            ["SOC2-CC8.1"], RiskLevel.low,
            metadata={"instance_type": "t3.medium"},
        ),
        _make_asset(
            "dev-sandbox", AssetType.server, None, "Engineering",
            Environment.development, DataClassification.public,
            "Developer sandbox environment for local testing",
            ["dev", "sandbox"], DiscoverySource.manual,
            [], RiskLevel.low,
            metadata={"purpose": "local development"},
        ),
        _make_asset(
            "corp-vpn", AssetType.network, "it@governlayer.ai", "IT",
            Environment.production, DataClassification.confidential,
            "Corporate VPN gateway for remote access",
            ["network", "vpn", "security"], DiscoverySource.manual,
            ["SOC2-CC6.6", "NIST-AC-17"], RiskLevel.high,
            metadata={"provider": "WireGuard", "concurrent_users": 89},
        ),
        _make_asset(
            "employee-laptops", AssetType.endpoint, "it@governlayer.ai", "IT",
            Environment.production, DataClassification.internal,
            "Fleet of managed employee endpoints (macOS and Windows)",
            ["endpoint", "mdm", "fleet"], DiscoverySource.manual,
            ["SOC2-CC6.7", "CIS-Benchmark-macOS"], RiskLevel.medium,
            metadata={"total_devices": 178, "mdm": "Jamf Pro", "encrypted": True},
        ),
    ]

    for asset in seeds:
        _assets[asset["id"]] = asset


def _ensure_seeded() -> None:
    if not _seeded:
        _seed_demo_assets()


# ---------------------------------------------------------------------------
# Helper: build aggregated stats
# ---------------------------------------------------------------------------

def _build_stats(assets: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    by_env: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for a in assets:
        by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        by_env[a["environment"]] = by_env.get(a["environment"], 0) + 1
        by_risk[a["risk_level"]] = by_risk.get(a["risk_level"], 0) + 1
    return {"by_type": by_type, "by_environment": by_env, "by_risk": by_risk}


# ---------------------------------------------------------------------------
# Discovery simulation
# ---------------------------------------------------------------------------

_DISCOVERY_TEMPLATES: dict[str, list[dict]] = {
    "aws": [
        {"name": "aws-ec2-web-{n}", "type": AssetType.server, "dept": "Engineering",
         "classification": DataClassification.internal, "risk": RiskLevel.medium,
         "tags": ["aws", "ec2", "compute"], "controls": ["SOC2-CC6.1"],
         "meta": {"provider": "AWS", "service": "EC2"}},
        {"name": "aws-rds-analytics-{n}", "type": AssetType.database, "dept": "Data",
         "classification": DataClassification.confidential, "risk": RiskLevel.high,
         "tags": ["aws", "rds", "analytics"], "controls": ["SOC2-CC6.1", "GDPR-Art32"],
         "meta": {"provider": "AWS", "service": "RDS", "engine": "PostgreSQL 15"}},
        {"name": "aws-s3-data-lake-{n}", "type": AssetType.storage, "dept": "Data",
         "classification": DataClassification.restricted, "risk": RiskLevel.high,
         "tags": ["aws", "s3", "data-lake"], "controls": ["SOC2-CC6.1"],
         "meta": {"provider": "AWS", "service": "S3", "encryption": "AES-256"}},
    ],
    "github": [
        {"name": "repo-backend-{n}", "type": AssetType.saas_app, "dept": "Engineering",
         "classification": DataClassification.confidential, "risk": RiskLevel.medium,
         "tags": ["github", "source-code", "backend"], "controls": ["SOC2-CC8.1"],
         "meta": {"platform": "GitHub", "visibility": "private"}},
        {"name": "repo-infra-{n}", "type": AssetType.saas_app, "dept": "Engineering",
         "classification": DataClassification.confidential, "risk": RiskLevel.high,
         "tags": ["github", "source-code", "infrastructure"], "controls": ["SOC2-CC8.1"],
         "meta": {"platform": "GitHub", "visibility": "private"}},
    ],
    "gcp": [
        {"name": "gcp-gke-cluster-{n}", "type": AssetType.container, "dept": "Engineering",
         "classification": DataClassification.confidential, "risk": RiskLevel.high,
         "tags": ["gcp", "gke", "kubernetes"], "controls": ["CIS-Benchmark-K8s"],
         "meta": {"provider": "GCP", "service": "GKE"}},
        {"name": "gcp-bigquery-{n}", "type": AssetType.database, "dept": "Data",
         "classification": DataClassification.restricted, "risk": RiskLevel.high,
         "tags": ["gcp", "bigquery", "analytics"], "controls": ["SOC2-CC6.1"],
         "meta": {"provider": "GCP", "service": "BigQuery"}},
    ],
    "okta": [
        {"name": "okta-app-salesforce-{n}", "type": AssetType.saas_app, "dept": "Sales",
         "classification": DataClassification.confidential, "risk": RiskLevel.medium,
         "tags": ["okta", "sso", "crm"], "controls": ["SOC2-CC6.1"],
         "meta": {"provider": "Okta", "mfa_required": True}},
        {"name": "okta-app-slack-{n}", "type": AssetType.saas_app, "dept": "IT",
         "classification": DataClassification.internal, "risk": RiskLevel.low,
         "tags": ["okta", "sso", "communication"], "controls": ["SOC2-CC6.1"],
         "meta": {"provider": "Okta", "mfa_required": True}},
    ],
    "datadog": [
        {"name": "dd-monitor-api-latency-{n}", "type": AssetType.api, "dept": "SRE",
         "classification": DataClassification.internal, "risk": RiskLevel.medium,
         "tags": ["datadog", "monitoring", "api"], "controls": ["SOC2-CC7.1"],
         "meta": {"provider": "Datadog", "monitor_type": "APM"}},
        {"name": "dd-host-web-{n}", "type": AssetType.server, "dept": "SRE",
         "classification": DataClassification.internal, "risk": RiskLevel.medium,
         "tags": ["datadog", "monitoring", "host"], "controls": ["SOC2-CC7.1"],
         "meta": {"provider": "Datadog", "agent_version": "7.x"}},
    ],
}


def _discover_assets(source: DiscoverySource) -> list[dict]:
    """Simulate asset discovery from a given integration source."""
    templates = _DISCOVERY_TEMPLATES.get(source.value, [])
    discovered = []
    suffix = uuid.uuid4().hex[:6]
    for tpl in templates:
        asset = _make_asset(
            name=tpl["name"].format(n=suffix),
            asset_type=tpl["type"],
            owner=None,
            department=tpl["dept"],
            environment=Environment.production,
            data_classification=tpl["classification"],
            description=f"Auto-discovered from {source.value} integration",
            tags=tpl["tags"],
            discovered_from=source,
            compliance_controls=tpl["controls"],
            risk_level=tpl["risk"],
            metadata=tpl["meta"],
            last_scanned=_now_iso(),
        )
        _assets[asset["id"]] = asset
        discovered.append(asset)
    return discovered


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/summary")
def asset_summary(email: str = Depends(verify_token)):
    """Dashboard summary of the full asset inventory."""
    _ensure_seeded()
    active = [a for a in _assets.values() if a["status"] != AssetStatus.decommissioned.value]
    stats = _build_stats(active)
    unclassified = sum(1 for a in active if a["data_classification"] is None)
    without_owner = sum(1 for a in active if not a["owner"])
    return {
        "total_assets": len(active),
        "total_decommissioned": sum(1 for a in _assets.values() if a["status"] == AssetStatus.decommissioned.value),
        "by_type": stats["by_type"],
        "by_environment": stats["by_environment"],
        "by_risk": stats["by_risk"],
        "unclassified_count": unclassified,
        "assets_without_owner": without_owner,
    }


@router.get("/data-map")
def data_classification_map(email: str = Depends(verify_token)):
    """Group active assets by data classification level."""
    _ensure_seeded()
    active = [a for a in _assets.values() if a["status"] != AssetStatus.decommissioned.value]
    classification_map: dict[str, dict] = {}

    for a in active:
        level = a["data_classification"] or "unclassified"
        if level not in classification_map:
            classification_map[level] = {"count": 0, "owners": set(), "assets": []}
        classification_map[level]["count"] += 1
        if a["owner"]:
            classification_map[level]["owners"].add(a["owner"])
        classification_map[level]["assets"].append({
            "id": a["id"],
            "name": a["name"],
            "type": a["type"],
            "owner": a["owner"],
            "environment": a["environment"],
        })

    # Convert sets to sorted lists for JSON serialization
    result = {}
    for level, data in classification_map.items():
        result[level] = {
            "count": data["count"],
            "owners": sorted(data["owners"]),
            "assets": data["assets"],
        }

    return {"data_classification_map": result}


@router.get("")
def list_assets(
    type: Optional[AssetType] = None,
    environment: Optional[Environment] = None,
    owner: Optional[str] = None,
    data_classification: Optional[DataClassification] = None,
    risk_level: Optional[RiskLevel] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    email: str = Depends(verify_token),
):
    """List assets with optional filtering and name search."""
    _ensure_seeded()
    assets = list(_assets.values())

    # Exclude decommissioned by default unless explicitly filtering
    assets = [a for a in assets if a["status"] != AssetStatus.decommissioned.value]

    if type is not None:
        assets = [a for a in assets if a["type"] == type.value]
    if environment is not None:
        assets = [a for a in assets if a["environment"] == environment.value]
    if owner is not None:
        assets = [a for a in assets if a["owner"] and owner.lower() in a["owner"].lower()]
    if data_classification is not None:
        assets = [a for a in assets if a["data_classification"] == data_classification.value]
    if risk_level is not None:
        assets = [a for a in assets if a["risk_level"] == risk_level.value]
    if search is not None:
        term = search.lower()
        assets = [a for a in assets if term in a["name"].lower()]

    stats = _build_stats(assets)
    limited = assets[:limit]

    return {
        "total": len(assets),
        "by_type": stats["by_type"],
        "by_environment": stats["by_environment"],
        "by_risk": stats["by_risk"],
        "assets": limited,
    }


@router.post("", status_code=201)
def create_asset(body: AssetCreate, email: str = Depends(verify_token)):
    """Manually register a new asset."""
    _ensure_seeded()
    asset = _make_asset(
        name=body.name,
        asset_type=body.type,
        owner=body.owner,
        department=body.department,
        environment=body.environment,
        data_classification=body.data_classification,
        description=body.description,
        tags=body.tags,
        discovered_from=body.discovered_from,
        compliance_controls=body.compliance_controls,
        risk_level=body.risk_level,
        metadata=body.metadata,
    )
    _assets[asset["id"]] = asset
    return asset


@router.post("/discover", status_code=201)
def discover_assets(body: DiscoverRequest, email: str = Depends(verify_token)):
    """Simulate auto-discovery of assets from a connected integration."""
    _ensure_seeded()
    if body.source == DiscoverySource.manual:
        raise HTTPException(status_code=400, detail="Cannot auto-discover from 'manual'. Use POST /v1/assets instead.")
    discovered = _discover_assets(body.source)
    return {
        "source": body.source.value,
        "discovered_count": len(discovered),
        "assets": discovered,
    }


@router.get("/{asset_id}")
def get_asset(asset_id: str, email: str = Depends(verify_token)):
    """Get a single asset by ID."""
    _ensure_seeded()
    asset = _assets.get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}")
def update_asset(asset_id: str, body: AssetUpdate, email: str = Depends(verify_token)):
    """Partially update an asset."""
    _ensure_seeded()
    asset = _assets.get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset["status"] == AssetStatus.decommissioned.value:
        raise HTTPException(status_code=409, detail="Cannot update a decommissioned asset")

    updates = body.model_dump(exclude_unset=True)
    for key, value in updates.items():
        if isinstance(value, Enum):
            asset[key] = value.value
        else:
            asset[key] = value
    asset["updated_at"] = _now_iso()
    return asset


@router.delete("/{asset_id}")
def decommission_asset(asset_id: str, email: str = Depends(verify_token)):
    """Soft-delete an asset by setting its status to decommissioned."""
    _ensure_seeded()
    asset = _assets.get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset["status"] == AssetStatus.decommissioned.value:
        raise HTTPException(status_code=409, detail="Asset is already decommissioned")

    asset["status"] = AssetStatus.decommissioned.value
    asset["updated_at"] = _now_iso()
    return {"detail": "Asset decommissioned", "id": asset_id, "name": asset["name"]}


@router.post("/{asset_id}/controls")
def map_controls(asset_id: str, body: ControlMapping, email: str = Depends(verify_token)):
    """Map compliance control IDs to an asset."""
    _ensure_seeded()
    asset = _assets.get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset["status"] == AssetStatus.decommissioned.value:
        raise HTTPException(status_code=409, detail="Cannot modify controls on a decommissioned asset")

    existing = set(asset["compliance_controls"])
    new_controls = [c for c in body.control_ids if c not in existing]
    asset["compliance_controls"].extend(new_controls)
    asset["updated_at"] = _now_iso()
    return {
        "id": asset_id,
        "added_controls": new_controls,
        "total_controls": asset["compliance_controls"],
    }
