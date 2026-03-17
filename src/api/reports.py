"""Regulatory Report Generation API."""

from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.reports.generator import (
    generate_eu_ai_act_report,
    generate_nist_ai_rmf_report,
    generate_iso_42001_report,
)

router = APIRouter(prefix="/v1/reports", tags=["Reports"])


class ReportRequest(BaseModel):
    system_name: str
    framework: str = "eu_ai_act"
    risk_tier: str = "high"
    context: Dict[str, Any] = Field(default_factory=dict)


@router.post("")
def generate_report(data: ReportRequest):
    """Generate a regulatory compliance report."""
    generators = {
        "eu_ai_act": lambda: generate_eu_ai_act_report(
            system_name=data.system_name,
            risk_tier=data.risk_tier,
            context=data.context,
        ),
        "nist_ai_rmf": lambda: generate_nist_ai_rmf_report(
            system_name=data.system_name,
            context=data.context,
        ),
        "iso_42001": lambda: generate_iso_42001_report(
            system_name=data.system_name,
            context=data.context,
        ),
    }

    generator = generators.get(data.framework)
    if not generator:
        return {
            "error": f"Unknown framework: {data.framework}",
            "available": list(generators.keys()),
        }

    return generator()


@router.get("/frameworks")
def list_report_frameworks():
    """List available regulatory frameworks for report generation."""
    return {
        "frameworks": [
            {
                "id": "eu_ai_act",
                "name": "EU AI Act",
                "description": "European Union Artificial Intelligence Act compliance assessment",
                "articles_covered": ["Art. 9", "Art. 10", "Art. 11", "Art. 13", "Art. 14", "Art. 15"],
            },
            {
                "id": "nist_ai_rmf",
                "name": "NIST AI RMF",
                "description": "NIST AI Risk Management Framework assessment",
                "functions_covered": ["Govern", "Map", "Measure", "Manage"],
            },
            {
                "id": "iso_42001",
                "name": "ISO 42001",
                "description": "ISO/IEC 42001 AI Management System assessment",
                "clauses_covered": ["4-Context", "5-Leadership", "6-Planning", "7-Support", "8-Operation", "9-Performance", "10-Improvement"],
            },
        ],
    }
