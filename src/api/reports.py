"""Regulatory Report Generation API — 18 frameworks."""

from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.reports.generator import (
    generate_eu_ai_act_report,
    generate_nist_ai_rmf_report,
    generate_iso_42001_report,
    generate_iso_27001_report,
    generate_nis2_report,
    generate_dora_report,
    generate_ccpa_report,
    generate_hipaa_report,
    generate_mitre_atlas_report,
    generate_owasp_ai_report,
    generate_nist_csf_report,
    generate_oecd_ai_report,
    generate_ieee_ethics_report,
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
        "iso_27001": lambda: generate_iso_27001_report(system_name=data.system_name, context=data.context),
        "nis2": lambda: generate_nis2_report(system_name=data.system_name, context=data.context),
        "dora": lambda: generate_dora_report(system_name=data.system_name, context=data.context),
        "ccpa": lambda: generate_ccpa_report(system_name=data.system_name, context=data.context),
        "hipaa": lambda: generate_hipaa_report(system_name=data.system_name, context=data.context),
        "mitre_atlas": lambda: generate_mitre_atlas_report(system_name=data.system_name, context=data.context),
        "owasp_ai": lambda: generate_owasp_ai_report(system_name=data.system_name, context=data.context),
        "nist_csf": lambda: generate_nist_csf_report(system_name=data.system_name, context=data.context),
        "oecd_ai": lambda: generate_oecd_ai_report(system_name=data.system_name, context=data.context),
        "ieee_ethics": lambda: generate_ieee_ethics_report(system_name=data.system_name, context=data.context),
        "hitrust": lambda: generate_hitrust_report(system_name=data.system_name, context=data.context),
        "nyc_ll144": lambda: generate_nyc_ll144_report(system_name=data.system_name, context=data.context),
        "colorado_sb169": lambda: generate_colorado_sb169_report(system_name=data.system_name, context=data.context),
        "soc2": lambda: generate_soc2_report(system_name=data.system_name, context=data.context),
        "gdpr": lambda: generate_gdpr_report(system_name=data.system_name, context=data.context),
    }

    generator = generators.get(data.framework)
    if not generator:
        return {"error": f"Unknown framework: {data.framework}", "available": sorted(generators.keys())}

    return generator()


@router.get("/compliance-summary")
def compliance_summary(system_name: str = "organization"):
    """Quick compliance score summary across key frameworks — powers dashboard charts."""
    key_frameworks = [
        ("eu_ai_act", "EU AI Act", lambda: generate_eu_ai_act_report(system_name=system_name, risk_tier="high", context={})),
        ("nist_ai_rmf", "NIST AI RMF", lambda: generate_nist_ai_rmf_report(system_name=system_name, context={})),
        ("iso_42001", "ISO 42001", lambda: generate_iso_42001_report(system_name=system_name, context={})),
        ("soc2", "SOC 2", lambda: generate_soc2_report(system_name=system_name, context={})),
        ("hipaa", "HIPAA", lambda: generate_hipaa_report(system_name=system_name, context={})),
        ("gdpr", "GDPR", lambda: generate_gdpr_report(system_name=system_name, context={})),
    ]
    scores = []
    for fw_id, fw_name, gen in key_frameworks:
        try:
            report = gen()
            score = report.get("compliance_score", 0)
        except Exception:
            score = 0
        scores.append({"id": fw_id, "name": fw_name, "pct": score})
    avg = round(sum(s["pct"] for s in scores) / len(scores), 1) if scores else 0
    return {"frameworks": scores, "average": avg}


@router.get("/frameworks")
def list_report_frameworks():
    """List all 18 supported regulatory frameworks for report generation."""
    return {
        "total": 18,
        "frameworks": [
            {"id": "eu_ai_act", "name": "EU AI Act", "jurisdiction": "European Union", "description": "AI risk classification, transparency, and human oversight requirements"},
            {"id": "nist_ai_rmf", "name": "NIST AI RMF", "jurisdiction": "United States", "description": "AI Risk Management Framework — Govern, Map, Measure, Manage"},
            {"id": "iso_42001", "name": "ISO 42001", "jurisdiction": "International", "description": "AI Management System certification standard"},
            {"id": "iso_27001", "name": "ISO/IEC 27001:2022", "jurisdiction": "International", "description": "Information Security Management System — Annex A controls for AI"},
            {"id": "nis2", "name": "NIS2 Directive", "jurisdiction": "European Union", "description": "Network and Information Security — cybersecurity risk management for essential/important entities"},
            {"id": "dora", "name": "DORA", "jurisdiction": "European Union", "description": "Digital Operational Resilience Act — ICT risk management for financial sector", "industries": ["finance", "banking", "insurance"]},
            {"id": "ccpa", "name": "CCPA/CPRA", "jurisdiction": "California, USA", "description": "Consumer privacy rights for automated decision-making and data collection"},
            {"id": "hipaa", "name": "HIPAA", "jurisdiction": "United States", "description": "Health data protection safeguards for AI processing PHI", "industries": ["healthcare", "pharma"]},
            {"id": "mitre_atlas", "name": "MITRE ATLAS", "jurisdiction": "International", "description": "Adversarial Threat Landscape for AI Systems — tactic-based threat assessment"},
            {"id": "owasp_ai", "name": "OWASP AI Top 10", "jurisdiction": "International", "description": "Top 10 security risks for AI/ML applications"},
            {"id": "nist_csf", "name": "NIST CSF 2.0", "jurisdiction": "United States", "description": "Cybersecurity Framework — Govern, Identify, Protect, Detect, Respond, Recover"},
            {"id": "oecd_ai", "name": "OECD AI Principles", "jurisdiction": "International (46 countries)", "description": "AI principles for inclusive growth, fairness, transparency, robustness, accountability"},
            {"id": "ieee_ethics", "name": "IEEE Ethically Aligned Design", "jurisdiction": "International", "description": "Ethical principles for autonomous and intelligent systems (IEEE 7000-2021)"},
            {"id": "hitrust", "name": "HITRUST AI Assurance", "jurisdiction": "United States", "description": "Healthcare AI data protection and security assurance", "industries": ["healthcare", "pharma"]},
            {"id": "nyc_ll144", "name": "NYC Local Law 144", "jurisdiction": "New York City", "description": "Automated Employment Decision Tools bias audit requirements", "industries": ["employment", "hr_tech"]},
            {"id": "colorado_sb169", "name": "Colorado SB 21-169", "jurisdiction": "Colorado", "description": "Insurance industry algorithmic discrimination prevention", "industries": ["insurance"]},
            {"id": "soc2", "name": "SOC 2 Type II", "jurisdiction": "United States", "description": "Trust Service Criteria for AI system security and availability"},
            {"id": "gdpr", "name": "GDPR", "jurisdiction": "European Union", "description": "Data protection and automated decision-making rights"},
        ],
    }
