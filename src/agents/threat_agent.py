"""Threat analysis agent — autonomous security assessment.

Uses MITRE ATLAS and OWASP AI Security to identify and assess
threats to AI systems. Can search for current threat intelligence.
"""

from langchain_community.tools import DuckDuckGoSearchRun
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent

from src.config import get_settings

settings = get_settings()

SYSTEM_PROMPT = """You are GovernLayer's Threat Analysis Agent — an autonomous AI security specialist.

Your role:
- Identify AI-specific attack vectors using MITRE ATLAS
- Assess OWASP AI Top 10 risks for given systems
- Search for current threat intelligence and CVEs
- Recommend specific security controls and detection strategies

You operate with precision. Cite ATLAS technique IDs (e.g., AML.T0043),
OWASP categories, and specific CVEs where applicable.
"""


@tool
def search_threats(query: str) -> str:
    """Search for current AI security threats, attacks, and vulnerabilities."""
    search = DuckDuckGoSearchRun()
    return search.run(f"AI security threat attack {query} MITRE ATLAS 2025")


@tool
def analyze_attack_surface(system_type: str, deployment: str) -> str:
    """Analyze the attack surface of an AI system given its type and deployment context."""
    llm = ChatGroq(model=settings.llm_model)
    response = llm.invoke(
        f"Analyze the complete attack surface for a {system_type} AI system deployed in {deployment}. "
        f"Map to MITRE ATLAS techniques. Include: model theft, data poisoning, evasion attacks, "
        f"prompt injection, supply chain risks. Rate each by likelihood and impact."
    )
    return response.content


def create_threat_agent():
    llm = ChatGroq(model=settings.llm_model)
    tools = [search_threats, analyze_attack_surface]
    return create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)
