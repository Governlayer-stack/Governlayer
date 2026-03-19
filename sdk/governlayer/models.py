"""GovernLayer SDK — typed response models.

All API responses are parsed into Pydantic models for type safety and
auto-completion support. Fields use ``None`` defaults so the SDK never
crashes when the server omits an optional field.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------

class DriftAnalysis(BaseModel):
    """Drift detection sub-result embedded in governance responses."""
    vetoed: bool = False
    drift_coefficient: float = 0.0
    semantic_risk_flags: int = 0
    explanation: str = ""
    keyword_flags: Optional[List[str]] = None
    manifold_distances: Optional[Dict[str, float]] = None

    class Config:
        extra = "allow"


class GovernanceDecision(BaseModel):
    """Response from ``POST /govern`` and ``POST /v1/govern``."""
    decision_id: str = ""
    system: str = ""
    governance_action: str = ""
    reason: str = ""
    drift_analysis: Optional[DriftAnalysis] = None
    risk_score: float = 0.0
    risk_level: str = ""
    dimension_scores: Optional[Dict[str, float]] = None
    current_hash: str = ""
    policy_version: str = ""
    timestamp: str = ""

    class Config:
        extra = "allow"


class ScanResult(BaseModel):
    """Response from ``POST /automate/scan``."""
    system: str = ""
    action: str = ""
    risk_score: float = 0.0
    risk_level: str = ""
    drift_coefficient: float = 0.0
    vetoed: bool = False
    dimension_scores: Optional[Dict[str, float]] = None
    timestamp: str = ""

    class Config:
        extra = "allow"


class DriftResult(BaseModel):
    """Response from ``POST /drift``."""
    vetoed: bool = False
    drift_coefficient: float = 0.0
    semantic_risk_flags: int = 0
    explanation: str = ""
    keyword_flags: Optional[List[str]] = None
    manifold_distances: Optional[Dict[str, float]] = None

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------

class RiskScore(BaseModel):
    """Response from ``POST /risk-score``."""
    system: str = ""
    overall_score: float = 0.0
    risk_level: str = ""
    dimension_scores: Optional[Dict[str, float]] = None
    scored_by: str = ""
    scored_at: str = ""

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

class AuditResult(BaseModel):
    """Response from ``POST /audit``."""
    decision_id: str = ""
    system: str = ""
    industry: str = ""
    audit_date: str = ""
    audited_by: str = ""
    governance_action: str = ""
    current_hash: str = ""
    previous_hash: str = ""
    policy_version: str = ""
    results: str = ""

    class Config:
        extra = "allow"


class AuditHistoryEntry(BaseModel):
    decision_id: str = ""
    system_name: str = ""
    governance_action: str = ""
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    current_hash: str = ""
    created_at: str = ""


class AuditHistoryResponse(BaseModel):
    total: int = 0
    page: int = 1
    per_page: int = 50
    pages: int = 0
    audits: List[AuditHistoryEntry] = Field(default_factory=list)

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportResult(BaseModel):
    """Response from ``POST /v1/reports``."""
    framework: Optional[str] = None
    system_name: Optional[str] = None
    compliance_score: Optional[float] = None
    risk_tier: Optional[str] = None

    class Config:
        extra = "allow"


class FrameworkScore(BaseModel):
    id: str = ""
    name: str = ""
    pct: float = 0.0


class ComplianceSummary(BaseModel):
    """Response from ``GET /v1/reports/compliance-summary``."""
    frameworks: List[FrameworkScore] = Field(default_factory=list)
    average: float = 0.0

    class Config:
        extra = "allow"


class FrameworkInfo(BaseModel):
    id: str = ""
    name: str = ""
    jurisdiction: str = ""
    description: str = ""
    industries: Optional[List[str]] = None


class FrameworkListResponse(BaseModel):
    total: int = 0
    frameworks: List[FrameworkInfo] = Field(default_factory=list)

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Agent Registry
# ---------------------------------------------------------------------------

class Agent(BaseModel):
    """Agent in the governance registry."""
    id: Optional[int] = None
    name: str = ""
    agent_type: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    team: Optional[str] = None
    purpose: Optional[str] = None
    tools: Optional[List[str]] = None
    data_sources: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    guardrails: Optional[List[str]] = None
    autonomy_level: Optional[int] = None
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    risk_tier: Optional[str] = None
    risk_score: Optional[float] = None
    governance_status: Optional[str] = None
    is_shadow: Optional[bool] = None
    discovery_source: Optional[str] = None
    tags: Optional[List[str]] = None
    dependencies: Optional[List[Dict[str, Any]]] = None
    created_at: Optional[str] = None

    class Config:
        extra = "allow"


class AgentListResponse(BaseModel):
    total: int = 0
    page: int = 1
    limit: int = 50
    pages: int = 0
    approved: int = 0
    shadow_detected: int = 0
    agents: List[Agent] = Field(default_factory=list)

    class Config:
        extra = "allow"


class AgentGovernanceResult(BaseModel):
    id: int = 0
    name: str = ""
    status: str = ""
    governance_status: str = ""

    class Config:
        extra = "allow"


class ShadowScanResult(BaseModel):
    """Response from ``POST /v1/agents/discovery/scan``."""
    scan_type: str = ""
    targets_scanned: int = 0
    total_detections: int = 0
    unregistered_ai: int = 0
    risk_level: str = ""
    detections: List[Dict[str, Any]] = Field(default_factory=list)
    recommendation: str = ""
    known_patterns: int = 0

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Model Registry
# ---------------------------------------------------------------------------

class RegisteredModel(BaseModel):
    """Model in the governance registry."""
    id: Optional[int] = None
    name: str = ""
    version: str = ""
    provider: Optional[str] = None
    model_type: Optional[str] = None
    lifecycle: Optional[str] = None
    risk_tier: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    governance_status: Optional[str] = None
    risk_score: Optional[float] = None
    last_audit_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        extra = "allow"


class ModelListResponse(BaseModel):
    total: int = 0
    page: int = 1
    limit: int = 50
    pages: int = 0
    models: List[RegisteredModel] = Field(default_factory=list)

    class Config:
        extra = "allow"


class LifecycleResult(BaseModel):
    id: int = 0
    name: str = ""
    lifecycle: str = ""

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

class Incident(BaseModel):
    id: Optional[int] = None
    title: str = ""
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    category: Optional[str] = None
    model_id: Optional[int] = None
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    impact: Optional[str] = None
    reporter: Optional[str] = None
    assignee: Optional[str] = None
    timeline: Optional[List[Dict[str, Any]]] = None
    created_at: Optional[str] = None
    resolved_at: Optional[str] = None

    class Config:
        extra = "allow"


class IncidentListResponse(BaseModel):
    total: int = 0
    page: int = 1
    limit: int = 50
    pages: int = 0
    incidents: List[Incident] = Field(default_factory=list)

    class Config:
        extra = "allow"


class IncidentUpdateResult(BaseModel):
    id: int = 0
    status: Optional[str] = None
    severity: Optional[str] = None
    updated_at: str = ""

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class Policy(BaseModel):
    id: Optional[int] = None
    name: str = ""
    description: Optional[str] = None
    version: str = ""
    rules: Optional[List[Dict[str, Any]]] = None
    rules_count: Optional[int] = None
    is_active: Optional[bool] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        extra = "allow"


class PolicyListResponse(BaseModel):
    total: int = 0
    policies: List[Policy] = Field(default_factory=list)

    class Config:
        extra = "allow"


class PolicyEvaluationResult(BaseModel):
    """Response from ``POST /v1/policies/evaluate``."""
    overall_result: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None
    policy_name: Optional[str] = None
    policy_version: Optional[str] = None

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------

class ThreatAnalysis(BaseModel):
    """Response from ``POST /threats``."""
    system_type: str = ""
    threats: str = ""
    analyzed_at: str = ""

    class Config:
        extra = "allow"


class IncidentResponsePlan(BaseModel):
    """Response from ``POST /incident-response``."""
    incident_type: str = ""
    system: str = ""
    response_plan: str = ""

    class Config:
        extra = "allow"


class JurisdictionMap(BaseModel):
    """Response from ``POST /jurisdiction``."""
    countries: str = ""
    regulations: str = ""

    class Config:
        extra = "allow"


class ComplianceDeadlines(BaseModel):
    """Response from ``GET /deadlines``."""
    region: str = ""
    deadlines: str = ""

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Analytics / Usage
# ---------------------------------------------------------------------------

class UsageSummary(BaseModel):
    """Response from ``GET /v1/analytics/usage/summary``."""
    period_days: int = 30
    total_requests: int = 0
    success_count: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    average_latency_ms: float = 0.0
    active_api_keys: int = 0
    requests_per_day: float = 0.0

    class Config:
        extra = "allow"


class UsageTrendPoint(BaseModel):
    period: Optional[str] = None
    requests: int = 0
    avg_latency_ms: float = 0.0
    errors: int = 0


class UsageTrends(BaseModel):
    """Response from ``GET /v1/analytics/usage/trends``."""
    granularity: str = "day"
    period_days: int = 30
    data_points: List[UsageTrendPoint] = Field(default_factory=list)

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class LedgerEntry(BaseModel):
    id: Optional[int] = None
    decision_id: str = ""
    system_name: str = ""
    governance_action: str = ""
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    policy_version: str = ""
    previous_hash: str = ""
    current_hash: str = ""
    created_at: str = ""


class LedgerResponse(BaseModel):
    total_records: int = 0
    page: int = 1
    per_page: int = 50
    pages: int = 0
    ledger: List[LedgerEntry] = Field(default_factory=list)

    class Config:
        extra = "allow"


class LedgerVerification(BaseModel):
    """Response from ``GET /ledger/verify``."""
    valid: bool = True
    total_records: int = 0
    broken_links: List[Dict[str, Any]] = Field(default_factory=list)
    message: Optional[str] = None

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class PipelineResult(BaseModel):
    """Response from ``POST /automate/full-pipeline``."""
    pipeline_id: str = ""
    system: str = ""
    governance_action: str = ""
    reason: str = ""
    risk_score: float = 0.0
    risk_level: str = ""
    drift_coefficient: float = 0.0
    stages: Optional[Dict[str, Any]] = None
    audit_report: Optional[str] = None
    threat_report: Optional[str] = None
    ledger_hash: str = ""
    policy_version: str = ""
    elapsed_seconds: float = 0.0
    timestamp: str = ""

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthStatus(BaseModel):
    """Response from ``GET /health``."""
    status: str = ""
    version: str = ""
    database: str = ""

    class Config:
        extra = "allow"


class ServiceHealth(BaseModel):
    """Response from ``GET /automate/health``."""
    timestamp: str = ""
    overall: str = ""
    services: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
