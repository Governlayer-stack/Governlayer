"""Regulatory Report Generation API — 8 frameworks."""

from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.reports.generator import (
    generate_eu_ai_act_report,
    generate_nist_ai_rmf_report,
    generate_iso_42001_report,
    generate_hitrust_report,
    generate_nyc_ll144_report,
    generate_colorado_sb169_report,
    generate_soc2_report,
    generate_gdpr_report,
)

router = APIRouter(prefix="/v1/reports", tags=["Reports"])


class ReportRequest(BaseModel):
    system_name: str
    framework: str = "eu_ai_act"
    risk_tier: str = "high"
    context: Dict[str, Any] = Field(default_factory=dict)


@router.post("")
def generate_report(data: ReportRequest):
    """Generate a regulatory compliance report for any supported framework."""
    generators = {
        "eu_ai_act": lambda: generate_eu_ai_act_report(system_name=data.system_name, risk_tier=data.risk_tier, context=data.context),
        "nist_ai_rmf": lambda: generate_nist_ai_rmf_report(system_name=data.system_name, context=data.context),
        "iso_42001": lambda: generate_iso_42001_report(system_name=data.system_name, context=data.context),
        "hitrust": lambda: generate_hitrust_report(system_name=data.system_name, context=data.context),
        "nyc_ll144": lambda: generate_nyc_ll144_report(system_name=data.system_name, context=data.context),
        "colorado_sb169": lambda: generate_colorado_sb169_report(system_name=data.system_name, context=data.context),
        "soc2": lambda: generate_soc2_report(system_name=data.system_name, context=data.context),
        "gdpr": lambda: generate_gdpr_report(system_name=data.system_name, context=data.context),
    }

    generator = generators.get(data.framework)
    if not generator:
        return {"error": f"Unknown framework: {data.framework}", "available": list(generators.keys())}

    return generator()


@router.get("/frameworks")
def list_report_frameworks():
    """List all 8 supported regulatory frameworks for report generation."""
    return {
        "total": 8,
        "frameworks": [
            {"id": "eu_ai_act", "name": "EU AI Act", "jurisdiction": "European Union", "description": "AI risk classification, transparency, and human oversight requirements"},
            {"id": "nist_ai_rmf", "name": "NIST AI RMF", "jurisdiction": "United States", "description": "AI Risk Management Framework — Govern, Map, Measure, Manage"},
            {"id": "iso_42001", "name": "ISO 42001", "jurisdiction": "International", "description": "AI Management System certification standard"},
            {"id": "hitrust", "name": "HITRUST AI Assurance", "jurisdiction": "United States", "description": "Healthcare AI data protection and security assurance", "industries": ["healthcare", "pharma"]},
            {"id": "nyc_ll144", "name": "NYC Local Law 144", "jurisdiction": "New York City", "description": "Automated Employment Decision Tools bias audit requirements", "industries": ["employment", "hr_tech"]},
            {"id": "colorado_sb169", "name": "Colorado SB 21-169", "jurisdiction": "Colorado", "description": "Insurance industry algorithmic discrimination prevention", "industries": ["insurance"]},
            {"id": "soc2", "name": "SOC 2 Type II", "jurisdiction": "United States", "description": "Trust Service Criteria for AI system security and availability"},
            {"id": "gdpr", "name": "GDPR", "jurisdiction": "European Union", "description": "Data protection and automated decision-making rights"},
        ],
    }
