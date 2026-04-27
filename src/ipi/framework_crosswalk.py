"""IPI-to-Compliance Framework Crosswalk.

Maps Indirect Prompt Injection controls to specific clauses across
14 compliance frameworks. Turns prompt injection from a vague AI risk
into auditable compliance evidence.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ControlMapping:
    framework: str
    clause: str
    clause_title: str
    requirement: str
    ipi_relevance: str


# ---------------------------------------------------------------------------
# Master crosswalk: IPI category -> framework clause mappings
# ---------------------------------------------------------------------------

_CROSSWALK: dict[str, list[ControlMapping]] = {
    "injection_surface": [
        ControlMapping("NIST_AI_RMF", "MAP 1.5", "Third-Party Data Risks", "Identify and document risks from third-party data sources", "External data is the primary IPI attack vector"),
        ControlMapping("NIST_AI_RMF", "MEASURE 2.6", "Adversarial Testing", "Test AI systems against adversarial inputs", "IPI is an adversarial input class requiring dedicated testing"),
        ControlMapping("ISO42001", "A.6.2.6", "Data Poisoning Controls", "Implement controls against training and inference data poisoning", "IPI injects malicious instructions via poisoned inference data"),
        ControlMapping("ISO42001", "A.6.2.7", "Adversarial Robustness", "Ensure AI system robustness against adversarial manipulation", "IPI is the primary adversarial attack on LLM-based systems"),
        ControlMapping("EU_AI_ACT", "Article 15", "Accuracy & Robustness", "High-risk AI systems shall be resilient against unauthorized third parties exploiting system vulnerabilities", "IPI directly exploits LLM vulnerabilities via injected instructions"),
        ControlMapping("EU_AI_ACT", "Article 9", "Risk Management", "Identify and mitigate risks, including reasonably foreseeable misuse", "IPI is a foreseeable attack vector for any agent with external data access"),
        ControlMapping("SOC2", "CC6.1", "Logical Access Controls", "Restrict logical access to information assets", "IPI bypasses logical access by hijacking the agent's authorized access"),
        ControlMapping("SOC2", "CC7.2", "System Monitoring", "Monitor system components for anomalies", "Detect IPI via anomalous agent behavior, unexpected tool calls"),
        ControlMapping("NIST_CSF", "PR.DS-1", "Data-at-Rest Protection", "Protect data-at-rest confidentiality and integrity", "IPI can exfiltrate data-at-rest through agent tool access"),
        ControlMapping("NIST_CSF", "DE.CM-1", "Network Monitoring", "Monitor networks for cybersecurity events", "Detect outbound data exfiltration from IPI-compromised agents"),
    ],
    "data_exfiltration": [
        ControlMapping("NIST_AI_RMF", "MANAGE 2.2", "AI Incident Response", "Establish mechanisms to respond to AI incidents", "Data exfiltration via IPI is a category of AI incident"),
        ControlMapping("GDPR", "Article 32", "Security of Processing", "Implement appropriate technical measures to ensure data security", "IPI-driven exfiltration is a processing security failure"),
        ControlMapping("GDPR", "Article 33", "Breach Notification", "Notify supervisory authority within 72 hours of data breach", "IPI-caused data leak triggers GDPR breach notification"),
        ControlMapping("HIPAA", "164.312(a)(1)", "Access Control", "Implement technical policies to allow access only to authorized persons", "IPI grants attacker access through the agent's existing permissions"),
        ControlMapping("HIPAA", "164.312(e)(1)", "Transmission Security", "Implement technical security measures for ePHI in transit", "IPI exfiltrates data via agent's outbound channels"),
        ControlMapping("PCI_DSS", "6.2.4", "Software Security", "Prevent common software attacks including injection", "Prompt injection is the LLM equivalent of SQL injection"),
        ControlMapping("PCI_DSS", "11.5.1", "Network Intrusion Detection", "Detect and alert on network intrusions", "Detect IPI-triggered data exfiltration to external endpoints"),
        ControlMapping("SOC2", "CC6.7", "Data Transmission Controls", "Restrict transmission of data to authorized parties", "IPI circumvents transmission controls via agent's authorized channels"),
        ControlMapping("CCPA", "1798.150", "Data Security", "Implement reasonable security measures", "IPI represents a failure of reasonable security measures for AI systems"),
    ],
    "instruction_hierarchy": [
        ControlMapping("NIST_AI_RMF", "GOVERN 1.4", "AI Risk Management Process", "Establish governance processes for AI risk", "Instruction hierarchy is a fundamental AI governance control"),
        ControlMapping("ISO42001", "A.5.4", "AI Policy", "Define and enforce AI policies and behavioral boundaries", "System prompt instruction hierarchy enforces AI behavioral policy"),
        ControlMapping("EU_AI_ACT", "Article 14", "Human Oversight", "Design AI for effective human oversight", "Instruction hierarchy preserves human control over agent behavior"),
        ControlMapping("ISO27001", "A.8.3", "Information Access Restriction", "Restrict access to information in accordance with access control policy", "Instruction hierarchy prevents unauthorized instruction execution"),
        ControlMapping("NIS2", "Article 21", "Cybersecurity Risk Management", "Implement appropriate risk management measures", "Instruction hierarchy is a risk management measure for AI systems"),
    ],
    "tool_abuse": [
        ControlMapping("NIST_AI_RMF", "MAP 3.5", "Trustworthiness Characteristics", "Identify AI system capabilities that could be misused", "Tool access without restrictions enables IPI-driven misuse"),
        ControlMapping("SOC2", "CC6.3", "Role-Based Access", "Manage access through role-based permissions", "Agent tools should follow least-privilege principle"),
        ControlMapping("ISO27001", "A.8.2", "Privileged Access Management", "Restrict and control privileged access", "Unrestricted tool access is excessive privilege"),
        ControlMapping("DORA", "Article 9", "ICT Risk Management", "Identify, classify and document ICT risks", "Unrestricted agent tools are classifiable ICT risks"),
        ControlMapping("PCI_DSS", "7.2.1", "Least Privilege", "Restrict access to system components to least privilege", "Each agent tool should have minimum necessary permissions"),
    ],
    "content_boundary": [
        ControlMapping("NIST_AI_RMF", "MEASURE 2.5", "Input Validation", "Validate AI system inputs against specifications", "Content boundaries validate that inputs are data, not instructions"),
        ControlMapping("ISO42001", "A.6.2.4", "Input Validation for AI", "Validate inputs to AI systems for integrity and expected format", "Boundary enforcement prevents untrusted content from acting as instructions"),
        ControlMapping("EU_AI_ACT", "Article 15.4", "Cybersecurity Measures", "Protect against unauthorized third parties exploiting vulnerabilities including data poisoning", "Content boundary enforcement is the primary defense against IPI"),
        ControlMapping("SOC2", "CC7.1", "Detection of Changes", "Detect unauthorized changes to system configuration", "Content boundaries detect when retrieved data attempts to change agent behavior"),
    ],
    "privilege_escalation": [
        ControlMapping("NIST_AI_RMF", "MANAGE 1.3", "Risk Response", "Prioritize and respond to identified AI risks", "Privilege escalation via IPI requires immediate risk response"),
        ControlMapping("ISO27001", "A.8.2", "Privileged Access Management", "Restrict and control allocation of privileged access rights", "IPI achieves privilege escalation by hijacking agent's permissions"),
        ControlMapping("SOC2", "CC6.1", "Logical Access Controls", "Implement logical access security over information assets", "Code execution tools require strongest access controls"),
        ControlMapping("HIPAA", "164.312(a)(2)(iv)", "Encryption and Decryption", "Implement mechanism to encrypt/decrypt ePHI", "Privilege escalation via agent tools could access encrypted health data"),
        ControlMapping("DORA", "Article 11", "ICT Response and Recovery", "Establish ICT incident response capabilities", "Privilege escalation incidents require defined response procedures"),
    ],
}


def get_crosswalk(category: Optional[str] = None) -> dict[str, list[dict]]:
    """Get the IPI-to-compliance framework crosswalk.

    Args:
        category: Optional filter by IPI category. If None, returns all.

    Returns:
        Dict mapping category -> list of control mappings.
    """
    result = {}
    categories = [category] if category and category in _CROSSWALK else _CROSSWALK.keys()

    for cat in categories:
        mappings = _CROSSWALK.get(cat, [])
        result[cat] = [
            {
                "framework": m.framework,
                "clause": m.clause,
                "clause_title": m.clause_title,
                "requirement": m.requirement,
                "ipi_relevance": m.ipi_relevance,
            }
            for m in mappings
        ]
    return result


def get_framework_controls(framework_code: str) -> list[dict]:
    """Get all IPI-relevant controls for a specific framework.

    Args:
        framework_code: Framework code (e.g., 'SOC2', 'GDPR', 'EU_AI_ACT').

    Returns:
        List of control mappings for that framework.
    """
    controls = []
    for category, mappings in _CROSSWALK.items():
        for m in mappings:
            if m.framework == framework_code:
                controls.append({
                    "category": category,
                    "clause": m.clause,
                    "clause_title": m.clause_title,
                    "requirement": m.requirement,
                    "ipi_relevance": m.ipi_relevance,
                })
    return controls


def map_findings_to_frameworks(findings: list) -> list[dict]:
    """Map scan findings to relevant compliance framework clauses.

    Args:
        findings: List of Finding objects from an IPI scan.

    Returns:
        List of dicts with finding_id, category, and applicable framework controls.
    """
    mapped = []
    for finding in findings:
        category = finding.category if isinstance(finding.category, str) else finding.category.value
        controls = get_crosswalk(category).get(category, [])
        if controls:
            mapped.append({
                "finding_id": finding.id,
                "finding_title": finding.title,
                "severity": finding.severity if isinstance(finding.severity, str) else finding.severity.value,
                "category": category,
                "applicable_controls": controls,
                "frameworks_affected": list({c["framework"] for c in controls}),
            })
    return mapped
