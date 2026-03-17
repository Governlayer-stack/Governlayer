"""Prompt Injection Defense & PII Detection — security guardrails for AI systems."""

import re
from typing import Dict, List


INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above\s+instructions",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous",
    r"you\s+are\s+now\s+(?:a|an)\s+",
    r"pretend\s+you\s+are",
    r"act\s+as\s+(?:a|an|if)\s+",
    r"roleplay\s+as",
    r"system\s*:\s*",
    r"\[system\]",
    r"\[INST\]",
    r"<\|im_start\|>",
    r"```\s*system",
    r"override\s+(?:your\s+)?(?:safety|content|rules)",
    r"bypass\s+(?:your\s+)?(?:safety|content|filter)",
    r"jailbreak",
    r"DAN\s+mode",
    r"developer\s+mode\s+enabled",
    r"do\s+anything\s+now",
    r"sudo\s+mode",
]

PII_PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone_us": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ssn": r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-.\s]?){3}\d{4}\b",
    "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
}


def scan_injection(text: str) -> Dict:
    """Scan text for prompt injection attempts."""
    findings = []
    text_lower = text.lower()

    for pattern in INJECTION_PATTERNS:
        matches = re.findall(pattern, text_lower)
        if matches:
            findings.append({
                "pattern": pattern,
                "matches": len(matches) if isinstance(matches[0], str) else len(matches),
                "severity": "high",
            })

    return {
        "injection_detected": len(findings) > 0,
        "risk_level": "critical" if len(findings) >= 3 else "high" if len(findings) >= 1 else "safe",
        "findings": findings,
        "total_patterns_checked": len(INJECTION_PATTERNS),
    }


def scan_pii(text: str) -> Dict:
    """Detect personally identifiable information in text."""
    findings = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            findings[pii_type] = {
                "count": len(matches),
                "samples": [m[:4] + "***" for m in matches[:3]],
            }

    return {
        "pii_detected": len(findings) > 0,
        "types_found": list(findings.keys()),
        "findings": findings,
    }


def redact_pii(text: str) -> Dict:
    """Redact PII from text and return sanitized version."""
    redacted = text
    redaction_count = 0

    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, redacted)
        redaction_count += len(matches)
        label = f"[REDACTED_{pii_type.upper()}]"
        redacted = re.sub(pattern, label, redacted)

    return {
        "original_length": len(text),
        "redacted_text": redacted,
        "redactions_made": redaction_count,
    }


def full_security_scan(text: str) -> Dict:
    """Combined injection + PII scan."""
    injection = scan_injection(text)
    pii = scan_pii(text)

    risk = "safe"
    if injection["injection_detected"] and pii["pii_detected"]:
        risk = "critical"
    elif injection["injection_detected"]:
        risk = "high"
    elif pii["pii_detected"]:
        risk = "medium"

    return {
        "overall_risk": risk,
        "safe": risk == "safe",
        "injection_scan": injection,
        "pii_scan": pii,
    }
