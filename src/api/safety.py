"""AI Safety & Bias Detection API — scan for bias, toxicity, and safety boundary gaps."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from src.safety.bias_scanner import scan_bias, scan_content_bias

router = APIRouter(prefix="/safety", tags=["AI Safety & Bias Detection"])


# ── Request models ──────────────────────────────────────────────────────────

class BiasScanRequest(BaseModel):
    system_name: str = Field(..., description="Name of the AI system to scan")
    system_prompt: Optional[str] = Field(None, description="System prompt to analyze for safety boundaries")
    model_output: Optional[str] = Field(None, description="Sample model output to scan for bias and toxicity")
    decisions: Optional[list] = Field(None, description="Decision records for disparate impact analysis. Each: {outcome, demographics: {gender, race, ...}}")


class ContentBiasRequest(BaseModel):
    content: str = Field(..., description="Content to scan for bias and toxicity")
    source: Optional[str] = Field(None, description="Source label (e.g. 'model_output', 'training_data', 'user_input')")


class FairnessReportRequest(BaseModel):
    system_name: str = Field(..., description="Name of the AI system")
    system_prompt: Optional[str] = None
    model_output: Optional[str] = None
    decisions: Optional[list] = None
    frameworks: Optional[list] = Field(None, description="Frameworks to map against: EU_AI_ACT, NIST_AI_RMF, ISO42001, GDPR, EEOC")


# ── Framework crosswalk ─────────────────────────────────────────────────────

BIAS_FRAMEWORK_CROSSWALK = {
    "EU_AI_ACT": {
        "Art10": {"title": "Data and Data Governance", "requirement": "Training data must be representative, free of errors, and appropriate. Bias examination and mitigation required.", "categories": ["disparate_impact", "stereotype", "safety_boundary"]},
        "Art9": {"title": "Risk Management System", "requirement": "Identify and mitigate risks of bias, including testing for disparate outcomes.", "categories": ["disparate_impact", "toxicity", "safety_boundary"]},
        "Art14": {"title": "Human Oversight", "requirement": "High-risk AI must allow human oversight to prevent/minimize bias risks.", "categories": ["safety_boundary"]},
        "Art52": {"title": "Transparency Obligations", "requirement": "Users must be informed they are interacting with AI.", "categories": ["safety_boundary"]},
        "Art68": {"title": "Right to Explanation", "requirement": "Individuals affected by AI decisions can request explanations.", "categories": ["safety_boundary", "disparate_impact"]},
    },
    "NIST_AI_RMF": {
        "GOVERN_1.4": {"title": "Governance — Oversight", "requirement": "Establish oversight mechanisms including human-in-the-loop for high-risk decisions.", "categories": ["safety_boundary"]},
        "GOVERN_1.7": {"title": "Governance — Safety", "requirement": "Processes to address safety and fairness concerns post-deployment.", "categories": ["safety_boundary", "toxicity"]},
        "MAP_1.6": {"title": "Map — Transparency", "requirement": "Document AI system capabilities, limitations, and potential biases.", "categories": ["safety_boundary"]},
        "MAP_2.3": {"title": "Map — Fairness", "requirement": "Identify and document potential sources of bias in AI systems.", "categories": ["disparate_impact", "stereotype", "sentiment_disparity"]},
        "MEASURE_2.5": {"title": "Measure — Data Quality", "requirement": "Evaluate training data for representativeness and bias.", "categories": ["disparate_impact", "safety_boundary"]},
        "MEASURE_2.6": {"title": "Measure — Fairness Metrics", "requirement": "Apply fairness metrics (demographic parity, equalized odds, disparate impact ratio).", "categories": ["disparate_impact"]},
        "MEASURE_3.2": {"title": "Measure — Monitoring", "requirement": "Monitor AI outputs for bias drift over time.", "categories": ["safety_boundary"]},
    },
    "ISO42001": {
        "6.1": {"title": "Actions to Address Risks", "requirement": "Plan actions to address AI risks including bias and fairness.", "categories": ["disparate_impact", "safety_boundary"]},
        "7.4": {"title": "Communication", "requirement": "Communicate AI use and limitations to stakeholders.", "categories": ["safety_boundary"]},
        "8.2": {"title": "AI Risk Assessment", "requirement": "Conduct risk assessment including bias and discrimination risks.", "categories": ["disparate_impact", "stereotype"]},
        "8.4": {"title": "AI System Development", "requirement": "Implement bias mitigation during AI system development.", "categories": ["safety_boundary", "stereotype"]},
        "9.1": {"title": "Monitoring, Measurement, Analysis", "requirement": "Monitor AI system performance for fairness and bias.", "categories": ["disparate_impact", "safety_boundary"]},
        "9.2": {"title": "Internal Audit", "requirement": "Conduct internal audits of AI fairness and compliance.", "categories": ["disparate_impact", "safety_boundary"]},
    },
    "GDPR": {
        "Art9": {"title": "Processing of Special Categories", "requirement": "Special categories of personal data (race, religion, health) require explicit consent and safeguards.", "categories": ["disparate_impact", "safety_boundary"]},
        "Art22": {"title": "Automated Individual Decision-Making", "requirement": "Right not to be subject to automated decision-making. Right to human intervention, express point of view, contest decision.", "categories": ["safety_boundary", "disparate_impact"]},
    },
    "EEOC": {
        "FOUR_FIFTHS": {"title": "Four-Fifths Rule", "requirement": "Selection rate for any group must be at least 80% of the group with the highest rate.", "categories": ["disparate_impact"]},
    },
}


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/bias/scan")
async def bias_scan(req: BiasScanRequest):
    """Scan an AI system for bias, stereotypes, toxicity, and safety boundary gaps.

    Provide any combination of:
    - system_prompt: Checked for missing safety boundaries (fairness statement, human oversight, etc.)
    - model_output: Scanned for stereotypes, sentiment disparity, and toxicity
    - decisions: Analyzed for disparate impact using the four-fifths rule
    """
    result = scan_bias(
        system_name=req.system_name,
        system_prompt=req.system_prompt,
        model_output=req.model_output,
        decisions=req.decisions,
    )
    return {
        "scan_id": result.scan_id,
        "system_name": result.system_name,
        "score": result.score,
        "risk_level": result.risk_level,
        "findings_count": result.findings_count,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "bias_categories_detected": result.bias_categories_detected,
        "protected_groups_affected": result.protected_groups_affected,
        "findings": result.findings,
        "summary": result.summary,
    }


@router.post("/bias/scan/content")
async def bias_scan_content(req: ContentBiasRequest):
    """Quick-scan content for bias and toxicity before an agent processes it.

    Use as middleware in your agent pipeline to catch biased or toxic
    content in retrieved documents, user messages, or model outputs.
    """
    return scan_content_bias(content=req.content, source=req.source)


@router.post("/fairness/report")
async def fairness_report(req: FairnessReportRequest):
    """Generate a fairness compliance report with framework mappings.

    Runs full bias scan and maps every finding to specific compliance
    framework clauses (EU AI Act, NIST AI RMF, ISO 42001, GDPR, EEOC).
    """
    result = scan_bias(
        system_name=req.system_name,
        system_prompt=req.system_prompt,
        model_output=req.model_output,
        decisions=req.decisions,
    )

    # Map findings to frameworks
    target_frameworks = req.frameworks or list(BIAS_FRAMEWORK_CROSSWALK.keys())
    framework_mappings = []

    for finding in result.findings:
        category = finding["category"]
        for fw_name in target_frameworks:
            fw = BIAS_FRAMEWORK_CROSSWALK.get(fw_name, {})
            for clause_id, clause_info in fw.items():
                if category in clause_info["categories"]:
                    framework_mappings.append({
                        "finding_id": finding["id"],
                        "finding_severity": finding["severity"],
                        "finding_category": category,
                        "framework": fw_name,
                        "clause": f"{fw_name}_{clause_id}" if fw_name != "EEOC" else clause_id,
                        "clause_title": clause_info["title"],
                        "requirement": clause_info["requirement"],
                    })

    return {
        "scan_id": result.scan_id,
        "system_name": result.system_name,
        "score": result.score,
        "risk_level": result.risk_level,
        "findings_count": result.findings_count,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "bias_categories_detected": result.bias_categories_detected,
        "protected_groups_affected": result.protected_groups_affected,
        "findings": result.findings,
        "framework_mappings": framework_mappings,
        "frameworks_assessed": target_frameworks,
        "summary": result.summary,
    }


@router.get("/bias/crosswalk")
async def bias_crosswalk(
    framework: Optional[str] = None,
    category: Optional[str] = None,
):
    """Get the bias-to-compliance framework control crosswalk.

    Maps bias categories to specific clauses across EU AI Act, NIST AI RMF,
    ISO 42001, GDPR, and EEOC.
    """
    results = []
    frameworks = {framework: BIAS_FRAMEWORK_CROSSWALK[framework]} if framework and framework in BIAS_FRAMEWORK_CROSSWALK else BIAS_FRAMEWORK_CROSSWALK

    for fw_name, clauses in frameworks.items():
        for clause_id, clause_info in clauses.items():
            if category and category not in clause_info["categories"]:
                continue
            results.append({
                "framework": fw_name,
                "clause": f"{fw_name}_{clause_id}" if fw_name != "EEOC" else clause_id,
                "clause_title": clause_info["title"],
                "requirement": clause_info["requirement"],
                "bias_categories": clause_info["categories"],
            })

    return {"controls": results, "total": len(results)}
