"""Compliance agent — autonomous framework scanning and gap analysis.

Uses LangGraph ReAct pattern with tools for:
- Searching current regulations
- Comparing system state against frameworks
- Generating compliance reports
"""

from langgraph.prebuilt import create_react_agent
from langchain_groq import ChatGroq
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_core.tools import tool

from src.config import get_settings

settings = get_settings()

SYSTEM_PROMPT = """You are GovernLayer's Compliance Agent — an autonomous AI governance specialist.

Your role:
- Audit AI systems against 25+ governance frameworks
- Identify compliance gaps with specific framework references
- Generate actionable remediation plans with deadlines
- Track regulatory changes across jurisdictions

Frameworks you specialize in: NIST AI RMF, EU AI Act, ISO 42001, MITRE ATLAS,
OWASP AI, SOC2, GDPR, CCPA, HIPAA, IEEE Ethics, OECD AI, UNESCO AI.

Always cite specific framework sections, articles, and requirements.
"""


@tool
def search_regulation(query: str) -> str:
    """Search for current AI regulations, laws, and compliance requirements."""
    search = DuckDuckGoSearchRun()
    return search.run(f"AI regulation compliance {query} 2025 2026")


@tool
def check_framework_requirement(framework: str, requirement: str) -> str:
    """Check a specific requirement within a governance framework."""
    llm = ChatGroq(model=settings.llm_model)
    response = llm.invoke(
        f"For the {framework} framework, detail this specific requirement: {requirement}. "
        f"Include: exact section/article number, what's required, who it applies to, "
        f"penalties for non-compliance, and implementation guidance."
    )
    return response.content


def create_compliance_agent():
    llm = ChatGroq(model=settings.llm_model)
    tools = [search_regulation, check_framework_requirement]
    return create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)
