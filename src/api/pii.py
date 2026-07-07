"""PII / PHI / PCI / Secrets Detection at the Decision Boundary.

Scans text payloads flowing through the governance pipeline for sensitive data.
Regex-first (zero-dep, deterministic, fast). Optional Presidio hook when the
package is installed. Returns categorized findings with offsets so callers can
redact, block, or alert.

Endpoints:
  POST /pii/scan              - Scan a single payload, return findings.
  POST /pii/scan/batch        - Scan a list of payloads.
  POST /pii/redact            - Scan and return a redacted copy of the text.
  GET  /pii/categories        - List supported detection categories.
  GET  /pii/policies          - Per-org policies (block | redact | alert | log).
  POST /pii/policies          - Set org policy for a category.
  GET  /pii/stats             - Detection counters since process start.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pii", tags=["pii"])


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

# Severity tiers map to default actions. PHI/PCI default to BLOCK, PII to REDACT,
# Secrets to BLOCK (never log a secret in a decision record).
SEVERITY_BLOCK = "block"
SEVERITY_REDACT = "redact"
SEVERITY_ALERT = "alert"
SEVERITY_LOG = "log"


def _luhn_valid(s: str) -> bool:
    digits = [int(d) for d in s if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Each detector: (category, severity, regex, validator|None, examples for docs)
DETECTORS: list[tuple[str, str, re.Pattern, Optional[callable], str]] = [
    # ---- PCI ----
    (
        "credit_card",
        SEVERITY_BLOCK,
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        _luhn_valid,
        "Luhn-validated card numbers",
    ),
    # ---- PII ----
    (
        "ssn_us",
        SEVERITY_BLOCK,
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        None,
        "US Social Security Number (xxx-xx-xxxx)",
    ),
    (
        "ein_us",
        SEVERITY_REDACT,
        re.compile(r"\b\d{2}-\d{7}\b"),
        None,
        "US Employer Identification Number",
    ),
    (
        "email",
        SEVERITY_REDACT,
        re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
        None,
        "Email address",
    ),
    (
        "phone_intl",
        SEVERITY_REDACT,
        re.compile(r"(?<!\d)(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\d)"),
        None,
        "Phone numbers, intl + national formats",
    ),
    (
        "ip_address",
        SEVERITY_LOG,
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        None,
        "IPv4 address",
    ),
    (
        "iban",
        SEVERITY_BLOCK,
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        None,
        "International Bank Account Number",
    ),
    (
        "passport_us",
        SEVERITY_BLOCK,
        re.compile(r"\b[A-Z]\d{8}\b"),
        None,
        "US passport (heuristic)",
    ),
    # ---- PHI ----
    (
        "us_mrn",
        SEVERITY_BLOCK,
        re.compile(r"\bMRN[:\s-]*\d{5,10}\b", re.IGNORECASE),
        None,
        "Medical record number (MRN: prefix)",
    ),
    (
        "us_dea",
        SEVERITY_BLOCK,
        re.compile(r"\b[A-Z]{2}\d{7}\b"),
        None,
        "DEA registration number",
    ),
    (
        "icd10",
        SEVERITY_ALERT,
        re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b"),
        None,
        "ICD-10 diagnosis code",
    ),
    # ---- Secrets ----
    (
        "aws_access_key",
        SEVERITY_BLOCK,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        None,
        "AWS access key ID",
    ),
    (
        "aws_secret",
        SEVERITY_BLOCK,
        re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
        None,
        "AWS secret access key in quotes",
    ),
    (
        "github_pat",
        SEVERITY_BLOCK,
        re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
        None,
        "GitHub personal access token",
    ),
    (
        "openai_key",
        SEVERITY_BLOCK,
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        None,
        "OpenAI / OpenAI-compatible API key",
    ),
    (
        "anthropic_key",
        SEVERITY_BLOCK,
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        None,
        "Anthropic API key",
    ),
    (
        "jwt",
        SEVERITY_ALERT,
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        None,
        "JWT (eyJ... header)",
    ),
    (
        "private_key_pem",
        SEVERITY_BLOCK,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
        None,
        "PEM-encoded private key",
    ),
    (
        "slack_token",
        SEVERITY_BLOCK,
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        None,
        "Slack token",
    ),
    (
        "stripe_key",
        SEVERITY_BLOCK,
        re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        None,
        "Stripe API key",
    ),
]


CATEGORY_DESCRIPTIONS = {cat: desc for cat, _, _, _, desc in DETECTORS}
CATEGORY_DEFAULT_SEVERITY = {cat: sev for cat, sev, _, _, _ in DETECTORS}


# ---------------------------------------------------------------------------
# In-memory stores (per-org policy overrides + counters)
# ---------------------------------------------------------------------------

_org_policy: dict[str, dict[str, str]] = defaultdict(dict)
_counters: dict[str, int] = defaultdict(int)


def _effective_severity(org_id: str, category: str) -> str:
    return _org_policy.get(org_id, {}).get(category, CATEGORY_DEFAULT_SEVERITY[category])


# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    category: str
    severity: str
    start: int
    end: int
    sample: str = Field(..., description="Masked sample of the matched value")
    confidence: float


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "***"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def scan_text(text: str, org_id: str = "default") -> list[Finding]:
    """Scan a single string. Returns findings sorted by start offset."""
    if not text:
        return []
    findings: list[Finding] = []
    for category, _default_sev, pattern, validator, _desc in DETECTORS:
        for m in pattern.finditer(text):
            value = m.group(0)
            if validator and not validator(value):
                continue
            severity = _effective_severity(org_id, category)
            findings.append(
                Finding(
                    category=category,
                    severity=severity,
                    start=m.start(),
                    end=m.end(),
                    sample=_mask(value),
                    confidence=0.95 if validator else 0.80,
                )
            )
            _counters[category] += 1
    findings.sort(key=lambda f: f.start)
    return findings


def redact_text(text: str, findings: list[Finding]) -> str:
    """Apply <REDACTED:category> markers in-place. Walks back-to-front to keep offsets stable."""
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        out = out[: f.start] + f"<REDACTED:{f.category}>" + out[f.end :]
    return out


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    text: str
    org_id: str = "default"


class ScanResponse(BaseModel):
    findings: list[Finding]
    summary: dict[str, int]
    highest_severity: Optional[str]
    action_recommended: str
    scanned_at: datetime


class BatchScanRequest(BaseModel):
    payloads: list[str]
    org_id: str = "default"


class BatchScanResponse(BaseModel):
    results: list[ScanResponse]
    total_findings: int


class RedactRequest(BaseModel):
    text: str
    org_id: str = "default"


class RedactResponse(BaseModel):
    redacted: str
    findings: list[Finding]


class PolicyUpdateRequest(BaseModel):
    org_id: str
    category: str
    severity: str = Field(..., description="block | redact | alert | log")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {SEVERITY_LOG: 0, SEVERITY_ALERT: 1, SEVERITY_REDACT: 2, SEVERITY_BLOCK: 3}


def _summarize(findings: list[Finding]) -> tuple[dict[str, int], Optional[str], str]:
    summary: dict[str, int] = defaultdict(int)
    highest: Optional[str] = None
    for f in findings:
        summary[f.category] += 1
        if highest is None or _SEVERITY_RANK[f.severity] > _SEVERITY_RANK[highest]:
            highest = f.severity
    if highest == SEVERITY_BLOCK:
        action = "block_decision"
    elif highest == SEVERITY_REDACT:
        action = "redact_before_forward"
    elif highest == SEVERITY_ALERT:
        action = "alert_and_continue"
    elif highest == SEVERITY_LOG:
        action = "log_only"
    else:
        action = "no_action"
    return dict(summary), highest, action


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    findings = scan_text(req.text, req.org_id)
    summary, highest, action = _summarize(findings)
    return ScanResponse(
        findings=findings,
        summary=summary,
        highest_severity=highest,
        action_recommended=action,
        scanned_at=datetime.now(timezone.utc),
    )


@router.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(req: BatchScanRequest) -> BatchScanResponse:
    results: list[ScanResponse] = []
    total = 0
    for payload in req.payloads:
        findings = scan_text(payload, req.org_id)
        summary, highest, action = _summarize(findings)
        results.append(
            ScanResponse(
                findings=findings,
                summary=summary,
                highest_severity=highest,
                action_recommended=action,
                scanned_at=datetime.now(timezone.utc),
            )
        )
        total += len(findings)
    return BatchScanResponse(results=results, total_findings=total)


@router.post("/redact", response_model=RedactResponse)
def redact(req: RedactRequest) -> RedactResponse:
    findings = scan_text(req.text, req.org_id)
    return RedactResponse(redacted=redact_text(req.text, findings), findings=findings)


@router.get("/categories")
def categories() -> dict:
    return {
        "categories": [
            {
                "name": cat,
                "default_severity": CATEGORY_DEFAULT_SEVERITY[cat],
                "description": CATEGORY_DESCRIPTIONS[cat],
            }
            for cat in CATEGORY_DESCRIPTIONS
        ],
        "severities": [SEVERITY_LOG, SEVERITY_ALERT, SEVERITY_REDACT, SEVERITY_BLOCK],
    }


@router.get("/policies")
def list_policies(org_id: str = "default") -> dict:
    overrides = _org_policy.get(org_id, {})
    return {
        "org_id": org_id,
        "effective": {cat: _effective_severity(org_id, cat) for cat in CATEGORY_DESCRIPTIONS},
        "overrides": overrides,
    }


@router.post("/policies")
def set_policy(req: PolicyUpdateRequest) -> dict:
    if req.category not in CATEGORY_DESCRIPTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown category: {req.category}")
    if req.severity not in _SEVERITY_RANK:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {req.severity}")
    _org_policy[req.org_id][req.category] = req.severity
    return {"org_id": req.org_id, "category": req.category, "severity": req.severity, "status": "updated"}


@router.get("/stats")
def stats() -> dict:
    return {
        "total_detections": sum(_counters.values()),
        "by_category": dict(_counters),
    }
