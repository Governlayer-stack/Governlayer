"""GovernLayer MCP Server — all tools registered BEFORE mcp.run().

Fixed: original had tools defined after mcp.run() making them unreachable.
"""

from fastmcp import FastMCP
from langchain_groq import ChatGroq
from langchain_community.tools import DuckDuckGoSearchRun
from dotenv import load_dotenv

load_dotenv()

mcp = FastMCP("GovernLayer AI Governance")
llm = ChatGroq(model="llama-3.3-70b-versatile")
search = DuckDuckGoSearchRun()

FRAMEWORKS = {
    "NIST_AI_RMF": "NIST AI Risk Management Framework",
    "EU_AI_ACT": "EU AI Act - risk based regulation",
    "ISO_42001": "ISO 42001 - AI management systems standard",
    "MITRE_ATLAS": "MITRE ATLAS - adversarial threat landscape",
    "OWASP_AI": "OWASP AI Security - top 10 AI security risks",
    "SOC2": "SOC 2 - security trust service criteria",
    "GDPR": "GDPR - EU data protection regulation",
    "CCPA": "CCPA - California consumer privacy act",
    "HIPAA": "HIPAA - healthcare data protection",
    "IEEE_ETHICS": "IEEE Ethics Guidelines - algorithmic bias prevention",
    "OECD_AI": "OECD AI Principles - human oversight and robustness",
    "UNESCO_AI": "UNESCO AI Ethics - human rights and fairness",
    "SINGAPORE_AI": "Singapore AI Governance Framework",
    "UK_AI": "UK AI Whitepaper - pro innovation regulation",
    "CANADA_AIDA": "Canada AIDA - high impact AI systems",
    "CHINA_AI": "China AI Regulations - algorithm recommendations",
    "COBIT": "COBIT - IT governance framework",
    "ITIL": "ITIL - IT service management",
    "ISO_27001": "ISO 27001 - information security management",
    "NIST_CSF": "NIST CSF - cybersecurity framework",
    "ZERO_TRUST": "Zero Trust Architecture - never trust always verify",
    "CIS_CONTROLS": "CIS Controls - critical security controls",
    "FAIR_RISK": "FAIR Risk Framework - information risk analysis",
    "CSA_AI": "Cloud Security Alliance AI guidance",
    "US_EO_AI": "US Executive Order on AI safety",
}


@mcp.tool()
def list_frameworks() -> str:
    """List all 25 AI governance frameworks in GovernLayer"""
    result = "# GovernLayer 25 AI Governance Frameworks\n\n"
    for i, (key, value) in enumerate(FRAMEWORKS.items(), 1):
        result += f"{i}. **{key}**: {value}\n"
    return result


@mcp.tool()
def calculate_risk_score(
    system_name: str,
    handles_personal_data: bool,
    makes_autonomous_decisions: bool,
    used_in_critical_infrastructure: bool,
    has_human_oversight: bool,
    is_explainable: bool,
    has_bias_testing: bool,
) -> str:
    """Calculate a risk score for an AI system across 6 dimensions"""
    scores = {
        "Privacy": 100 if not handles_personal_data else 40,
        "Autonomy_Risk": 100 if not makes_autonomous_decisions else 30,
        "Infrastructure_Risk": 100 if not used_in_critical_infrastructure else 25,
        "Oversight": 100 if has_human_oversight else 20,
        "Transparency": 100 if is_explainable else 30,
        "Fairness": 100 if has_bias_testing else 25,
    }
    overall = sum(scores.values()) / len(scores)
    if overall >= 80:
        risk_level = "LOW RISK GREEN"
    elif overall >= 50:
        risk_level = "MEDIUM RISK AMBER"
    else:
        risk_level = "HIGH RISK RED"
    result = f"# Risk Score: {system_name}\n## Overall: {overall:.0f}/100 {risk_level}\n\n"
    for dimension, score in scores.items():
        bar = "X" * (score // 10) + "." * (10 - score // 10)
        result += f"- **{dimension}**: [{bar}] {score}/100\n"
    return result


@mcp.tool()
def search_regulations(query: str) -> str:
    """Search for latest AI regulations and governance news"""
    results = search.run(f"AI governance regulation {query} 2025")
    prompt = f"Summarize these AI governance search results:\n{results}\nBe concise and actionable."
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def audit_ai_system(system_name: str, system_description: str, industry: str) -> str:
    """Audit an AI system against the top governance frameworks"""
    prompt = (
        f"You are a world class AI governance auditor. Audit this system:\n"
        f"System: {system_name}\nDescription: {system_description}\nIndustry: {industry}\n\n"
        f"Audit against NIST AI RMF, EU AI Act, ISO 42001, GDPR and OWASP AI.\n"
        f"For each framework provide compliance status, gaps found and recommendations."
    )
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def get_framework_details(framework_name: str) -> str:
    """Get detailed information about a specific governance framework"""
    if framework_name not in FRAMEWORKS:
        return f"Framework not found. Available: {', '.join(FRAMEWORKS.keys())}"
    prompt = (
        f"Give a comprehensive compliance guide for {framework_name}: {FRAMEWORKS[framework_name]}. "
        f"Include requirements, who it applies to, penalties and implementation steps."
    )
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def analyze_policy_gaps(company_name: str, existing_policies: str, industry: str) -> str:
    """Analyze gaps between existing company policies and all 25 governance frameworks"""
    prompt = (
        f"You are a senior AI governance consultant. Analyze policy gaps for:\n\n"
        f"Company: {company_name}\nIndustry: {industry}\nExisting Policies: {existing_policies}\n\n"
        f"Compare against NIST AI RMF, EU AI Act, ISO 42001, GDPR, HIPAA, SOC2 and OWASP AI.\n\n"
        f"For each framework identify:\n"
        f"1. What policies already exist and are covered\n"
        f"2. Critical gaps that must be addressed immediately\n"
        f"3. Recommended new policies to create\n"
        f"4. Priority level: CRITICAL / HIGH / MEDIUM / LOW\n\n"
        f"Format as a professional gap analysis report."
    )
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def map_jurisdiction_requirements(countries: str, industry: str, ai_system_type: str) -> str:
    """Map which AI regulations apply based on countries and industry"""
    prompt = (
        f"You are an expert in global AI regulation. Map requirements for:\n\n"
        f"Countries of operation: {countries}\nIndustry: {industry}\n"
        f"AI System Type: {ai_system_type}\n\n"
        f"For each country identify:\n"
        f"1. Applicable AI regulations and laws\n"
        f"2. Compliance deadlines\n"
        f"3. Penalties for non-compliance\n"
        f"4. Required certifications or registrations\n"
        f"5. Data residency requirements\n\n"
        f"Be specific with law names, article numbers and deadlines."
    )
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def generate_incident_response_plan(incident_type: str, ai_system_name: str, affected_users: str, industry: str) -> str:
    """Generate an AI incident response plan when an AI system fails or is attacked"""
    prompt = (
        f"You are a world class AI incident response expert. Generate a response plan:\n\n"
        f"Incident Type: {incident_type}\nAI System: {ai_system_name}\n"
        f"Affected Users: {affected_users}\nIndustry: {industry}\n\n"
        f"Create a detailed incident response plan including:\n"
        f"1. Immediate containment steps (first 1 hour)\n"
        f"2. Assessment and investigation steps\n"
        f"3. Regulatory notification requirements and deadlines\n"
        f"4. Stakeholder communication templates\n"
        f"5. Recovery and remediation steps\n"
        f"6. Post-incident review process\n"
        f"7. Relevant frameworks: NIST AI RMF, EU AI Act, ISO 27001\n\n"
        f"Make it actionable with specific timelines."
    )
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def track_compliance_deadlines(region: str) -> str:
    """Track upcoming AI regulatory compliance deadlines globally"""
    results = search.run(f"AI regulation compliance deadline 2025 2026 {region}")
    prompt = (
        f"You are an AI regulatory expert. Based on these search results:\n\n{results}\n\n"
        f"Create a compliance deadline tracker for {region} including:\n"
        f"1. Regulation name\n2. Deadline date\n3. Who it applies to\n"
        f"4. What must be done\n5. Penalties for missing deadline\n\n"
        f"Sort by urgency with most urgent first."
    )
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def analyze_ai_threats(system_type: str, deployment_context: str) -> str:
    """Analyze AI-specific threats using MITRE ATLAS and OWASP AI Security frameworks"""
    results = search.run(f"MITRE ATLAS AI attacks {system_type} threats 2025")
    prompt = (
        f"You are an AI security expert specializing in MITRE ATLAS and OWASP AI Security.\n\n"
        f"System Type: {system_type}\nDeployment Context: {deployment_context}\n\n"
        f"Search Results: {results}\n\n"
        f"Analyze threats including:\n"
        f"1. Most likely attack vectors for this system type\n"
        f"2. MITRE ATLAS techniques that apply\n"
        f"3. OWASP AI Top 10 risks that apply\n"
        f"4. Specific vulnerabilities to watch for\n"
        f"5. Recommended security controls\n"
        f"6. Detection and monitoring strategies\n\n"
        f"Be specific and technical."
    )
    response = llm.invoke(prompt)
    return response.content


@mcp.tool()
def achonye_route(task: str, prefer_local: bool = True) -> str:
    """Route a task through Achonye's intelligent multi-LLM system.

    Achonye analyzes the task complexity and routes to the optimal model:
    - Trivial/simple -> local Ollama models (zero cost, full privacy)
    - Moderate -> Groq or standard cloud models
    - Complex -> Board consultation (multiple senior models)
    - Critical -> Consensus validation (multi-LLM voting/debate)
    """
    from src.llm.router import route_task
    decision = route_task(task, prefer_local=prefer_local)
    return (
        f"# Achonye Routing Decision\n\n"
        f"- **Task Complexity**: {decision.task_complexity.value}\n"
        f"- **Capability Needed**: {decision.capability_needed.value}\n"
        f"- **Primary Model**: {decision.primary_model}\n"
        f"- **Reason**: {decision.reason}\n"
        f"- **Requires Consensus**: {decision.requires_consensus}\n"
    )


@mcp.tool()
def achonye_ecosystem() -> str:
    """View the full Achonye multi-LLM ecosystem — all models, hierarchy, status."""
    from src.llm.providers import MODEL_REGISTRY, ModelTier
    result = "# Achonye Ecosystem\n\n"
    result += "## Hierarchy\n"
    result += "- **Leader**: Claude Opus 4.6 (Achonye)\n"
    result += "- **Board**: Claude Sonnet, Gemini Pro, GPT-4o\n"
    result += "- **Validator**: Multi-LLM Consensus Engine\n"
    result += "- **Operators**: See below\n\n"

    for tier in ModelTier:
        models = [p for p in MODEL_REGISTRY.values() if p.tier == tier]
        if models:
            result += f"## {tier.value.upper()} Models ({len(models)})\n"
            for m in models:
                caps = ", ".join(c.value for c in m.capabilities)
                result += f"- **{m.name}** ({m.provider}): {caps}\n"
            result += "\n"

    result += f"\n**Total Models**: {len(MODEL_REGISTRY)}\n"
    return result


# ALL tools registered above — now run
if __name__ == "__main__":
    print("GovernLayer MCP Server starting...")
    print(f"{len(FRAMEWORKS)} governance frameworks loaded")
    print("12 tools registered (including Achonye)")
    mcp.run()
