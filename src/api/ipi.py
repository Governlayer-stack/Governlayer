"""IPI (Indirect Prompt Injection) scanning endpoints.

Deterministic scanner — no LLM calls, instant results.
Analyzes agent configurations for injection vulnerabilities
and maps findings to compliance framework clauses.
"""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.ipi.framework_crosswalk import get_crosswalk, get_framework_controls, map_findings_to_frameworks
from src.ipi.scanner import scan_agent
from src.security.auth import verify_token

router = APIRouter(prefix="/ipi", tags=["IPI Scanner"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ToolDefinition(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    restrictions: Optional[dict] = None
    allowlist: Optional[list[str]] = None
    constraints: Optional[dict] = None


class IPIScanRequest(BaseModel):
    system_name: str = Field(..., min_length=1, max_length=255, description="Name of the agent or system to scan")
    system_prompt: str = Field(default="", max_length=100000, description="The agent's system prompt")
    tools: list[ToolDefinition] = Field(default_factory=list, description="Agent's tool definitions")
    content: Optional[str] = Field(default=None, max_length=100000, description="Retrieved/user content to scan for injections")


class ContentScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=100000, description="Content to scan for injection payloads")
    source: str = Field(default="unknown", max_length=255, description="Source of the content (email, document, api, etc.)")


class FindingResponse(BaseModel):
    id: str
    category: str
    severity: str
    title: str
    description: str
    remediation: str
    evidence: str = ""
    atlas_id: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    system_name: str
    score: float
    risk_level: str
    findings_count: int
    critical_count: int
    high_count: int
    findings: list[FindingResponse]
    framework_mappings: list[dict]
    summary: str
    scanned_at: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanResponse)
def ipi_scan(request: IPIScanRequest, email: str = Depends(verify_token)):
    """Scan an agent configuration for Indirect Prompt Injection vulnerabilities.

    Analyzes system prompts, tool definitions, and content for:
    - Missing instruction hierarchy defenses
    - Data boundary violations
    - Tool-call exfiltration paths
    - Injection payloads in content
    - Privilege escalation risks

    Returns findings mapped to compliance framework clauses (NIST AI RMF,
    ISO 42001, EU AI Act, SOC 2, GDPR, HIPAA, PCI DSS, etc.).
    """
    scan_id = str(uuid.uuid4())
    tools_dicts = [t.model_dump() for t in request.tools]

    result = scan_agent(
        system_name=request.system_name,
        scan_id=scan_id,
        system_prompt=request.system_prompt,
        tools=tools_dicts,
        content=request.content,
    )

    framework_mappings = map_findings_to_frameworks(result.findings)

    findings_response = [
        FindingResponse(
            id=f.id,
            category=f.category.value if hasattr(f.category, 'value') else f.category,
            severity=f.severity.value if hasattr(f.severity, 'value') else f.severity,
            title=f.title,
            description=f.description,
            remediation=f.remediation,
            evidence=f.evidence,
            atlas_id=f.atlas_id,
        )
        for f in result.findings
    ]

    return ScanResponse(
        scan_id=scan_id,
        system_name=request.system_name,
        score=result.score,
        risk_level=result.risk_level,
        findings_count=len(result.findings),
        critical_count=sum(1 for f in result.findings if f.severity.value == "CRITICAL"),
        high_count=sum(1 for f in result.findings if f.severity.value == "HIGH"),
        findings=findings_response,
        framework_mappings=framework_mappings,
        summary=result.summary,
        scanned_at=result.scanned_at,
    )


@router.post("/scan/content")
def ipi_scan_content(request: ContentScanRequest, email: str = Depends(verify_token)):
    """Scan raw content for injection payloads before passing it to an agent.

    Use this as a pre-processing step: scan emails, documents, API responses,
    or any external data for injection attempts before your agent processes them.
    """
    scan_id = str(uuid.uuid4())
    result = scan_agent(
        system_name=f"content-scan-{request.source}",
        scan_id=scan_id,
        content=request.content,
    )

    return {
        "scan_id": scan_id,
        "source": request.source,
        "is_safe": result.risk_level == "LOW" and len(result.findings) == 0,
        "risk_level": result.risk_level,
        "injection_detected": any(
            f.category.value == "injection_surface" for f in result.findings
        ),
        "findings_count": len(result.findings),
        "findings": [
            {
                "id": f.id,
                "severity": f.severity.value,
                "title": f.title,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
        "scanned_at": result.scanned_at,
    }


@router.get("/crosswalk")
def ipi_crosswalk(
    category: Optional[str] = None,
    framework: Optional[str] = None,
    email: str = Depends(verify_token),
):
    """Get the IPI-to-compliance framework control crosswalk.

    Maps IPI vulnerability categories to specific compliance framework clauses
    across NIST AI RMF, ISO 42001, EU AI Act, SOC 2, GDPR, HIPAA, PCI DSS,
    NIST CSF, CCPA, NIS2, DORA, and ISO 27001.

    Filter by category (injection_surface, data_exfiltration, instruction_hierarchy,
    tool_abuse, content_boundary, privilege_escalation) or by framework code.
    """
    if framework:
        controls = get_framework_controls(framework.upper())
        return {
            "framework": framework.upper(),
            "ipi_controls": controls,
            "total": len(controls),
        }

    crosswalk = get_crosswalk(category)
    total = sum(len(v) for v in crosswalk.values())
    return {
        "crosswalk": crosswalk,
        "categories": list(crosswalk.keys()),
        "total_controls": total,
    }
