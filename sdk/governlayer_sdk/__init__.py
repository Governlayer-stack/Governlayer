"""GovernLayer SDK — the runtime enforcement point for AI evaluation.

The SDK is the artifact a lab CTO integrates. It wraps an eval harness so
every tool call the agent makes is pre-flighted through GovernLayer's
policy engine before it executes. If the policy engine says BLOCK, the
tool call never happens.

Minimal usage:

    from governlayer_sdk import Client, guard

    gl = Client(api_key="gl_...", base_url="https://api.governlayer.ai")

    @guard(gl, agent_id=42)
    def call_tool(name: str, args: dict) -> str:
        return original_tool_runner(name, args)

    # Any invocation of call_tool now hits /govern before executing.
    # BLOCK verdicts raise BlockedByPolicy.

For the Aug 2026 OpenAI/HuggingFace/Meta/Anthropic incident class of
failures — agents escaping eval sandboxes via lateral network moves —
the recommended pattern is:

    1. gl.attest(target_system="artifactory", action_type="write", ...)
       BEFORE the run. Produces a signed unilateral attestation.
    2. Every tool call through @guard.
    3. gl.scan_spec_gaming(agent_id=...) between eval rounds.
    4. On any escalation, gl.batch_lockdown(batch_id="...") kills all
       agents sharing the batch atomically.

Zero external dependencies beyond urllib.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional

__version__ = "0.1.0"


class GovernLayerError(Exception):
    """Base error for SDK failures."""


class BlockedByPolicy(GovernLayerError):
    """Raised when a policy verdict is BLOCK. Attribute .verdict has the full response."""
    def __init__(self, verdict: dict):
        self.verdict = verdict
        super().__init__(
            f"blocked by policy: {verdict.get('reason') or verdict.get('governance_action')}"
        )


class EscalatedToHuman(GovernLayerError):
    """Raised when a policy verdict is ESCALATE_HUMAN and the caller opted to block on escalation."""
    def __init__(self, verdict: dict):
        self.verdict = verdict
        super().__init__(
            f"escalated to human: {verdict.get('reason') or verdict.get('governance_action')}"
        )


@dataclass
class Verdict:
    action: str        # "APPROVE" | "ESCALATE_HUMAN" | "BLOCK"
    risk_score: float
    risk_level: str
    decision_id: str
    current_hash: str
    reason: str
    raw: dict


class Client:
    """Thin urllib-based client for the GovernLayer API.

    No async, no third-party deps. If you need async, wrap Client.govern()
    in your framework's executor — call takes a few tens of ms.
    """

    def __init__(self, api_key: str, base_url: str = "https://web-production-bdd26.up.railway.app",
                 timeout_seconds: float = 10.0):
        if not api_key or not api_key.startswith(("gl_", "eyJ")):
            raise ValueError("api_key must be a GovernLayer API key (gl_...) or a JWT")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds

    # -----------------------------------------------------------------
    # Low-level HTTP
    # -----------------------------------------------------------------

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        data = json.dumps(body, default=str).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": f"governlayer-sdk/{__version__}",
            },
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            body_text = ""
            try:
                body_text = exc.read().decode("utf-8")
            except Exception:  # noqa: BLE001
                pass
            raise GovernLayerError(f"HTTP {exc.code} on {method} {path}: {body_text[:500]}") from exc
        except urllib.error.URLError as exc:
            raise GovernLayerError(f"network error on {method} {path}: {exc}") from exc
        finally:
            self.last_latency_ms = round((time.perf_counter() - started) * 1000, 2)

    # -----------------------------------------------------------------
    # Governance / policy
    # -----------------------------------------------------------------

    def govern(self, *, system_name: str, reasoning_trace: str, use_case: str = "evaluation",
               makes_autonomous_decisions: bool = True,
               used_in_critical_infrastructure: bool = False,
               handles_personal_data: bool = False,
               has_human_oversight: bool = True,
               is_explainable: bool = True,
               has_bias_testing: bool = False,
               **extra: Any) -> Verdict:
        """Pre-flight a decision. Returns a Verdict; raises on BLOCK if configured."""
        body = {
            "system_name": system_name,
            "reasoning_trace": reasoning_trace,
            "use_case": use_case,
            "makes_autonomous_decisions": makes_autonomous_decisions,
            "used_in_critical_infrastructure": used_in_critical_infrastructure,
            "handles_personal_data": handles_personal_data,
            "has_human_oversight": has_human_oversight,
            "is_explainable": is_explainable,
            "has_bias_testing": has_bias_testing,
            **extra,
        }
        resp = self._request("POST", "/govern", body)
        return Verdict(
            action=resp.get("governance_action", "UNKNOWN"),
            risk_score=float(resp.get("risk_score", 0)),
            risk_level=resp.get("risk_level", "UNKNOWN"),
            decision_id=resp.get("decision_id", ""),
            current_hash=resp.get("current_hash", ""),
            reason=resp.get("reason", ""),
            raw=resp,
        )

    # -----------------------------------------------------------------
    # ERG
    # -----------------------------------------------------------------

    def activate_eval_mode(self, reason: str, *, downgraded_categories: Optional[str] = None,
                           elevated_categories: Optional[str] = None) -> dict:
        body: dict = {"reason": reason}
        if downgraded_categories: body["downgraded_categories"] = downgraded_categories
        if elevated_categories:  body["elevated_categories"] = elevated_categories
        return self._request("POST", "/v1/erg/eval-mode/activate", body)

    def deactivate_eval_mode(self) -> dict:
        return self._request("POST", "/v1/erg/eval-mode/deactivate", {})

    def get_eval_mode(self) -> dict:
        return self._request("GET", "/v1/erg/eval-mode")

    def attest(self, *, target_system: str, action_type: str, scope_summary: str,
               target_endpoint: Optional[str] = None,
               agent_id: Optional[int] = None,
               batch_id: Optional[str] = None,
               valid_for_hours: int = 1) -> dict:
        """Emit a signed unilateral attestation BEFORE touching an external system.

        Call this before every eval run that will reach an external service.
        Even in unilateral v0 form, it produces regulator-visible proof of
        what you announced you were about to do.
        """
        body = {
            "target_system": target_system,
            "target_endpoint": target_endpoint,
            "action_type": action_type,
            "scope_summary": scope_summary,
            "agent_id": agent_id,
            "batch_id": batch_id,
            "valid_for_hours": valid_for_hours,
        }
        return self._request("POST", "/v1/erg/attestations/emit", body)

    def revoke_attestation(self, attestation_id: str, reason: str) -> dict:
        return self._request("POST", f"/v1/erg/attestations/{attestation_id}/revoke",
                             {"reason": reason})

    def scan_spec_gaming(self, agent_id: int, *, lookback_minutes: int = 15,
                         similarity_threshold: float = 0.82,
                         auto_escalate: bool = True) -> dict:
        return self._request("POST", f"/v1/erg/spec-gaming/scan/{agent_id}", {
            "lookback_minutes": lookback_minutes,
            "similarity_threshold": similarity_threshold,
            "auto_escalate": auto_escalate,
        })

    def batch_lockdown(self, batch_id: str, reason: str,
                       triggered_by: str = "operator") -> dict:
        return self._request("POST", f"/v1/erg/circuit-breaker/lockdown/{batch_id}",
                             {"reason": reason, "triggered_by": triggered_by})

    def kill_agent(self, agent_id: int, reason: str, kill_source: str = "operator") -> dict:
        return self._request("POST", f"/v1/agents/{agent_id}/kill",
                             {"reason": reason, "kill_source": kill_source})

    def issue_eval_credential(self, agent_id: int, name: str, ttl_hours: int = 4) -> dict:
        return self._request("POST", f"/v1/agents/{agent_id}/credentials/eval",
                             {"name": name, "ttl_hours": ttl_hours})

    def verify_ledger(self) -> dict:
        return self._request("GET", "/ledger/verify")


# -----------------------------------------------------------------
# Decorator for wrapping an eval harness tool runner
# -----------------------------------------------------------------


def guard(client: Client, *, agent_id: Optional[int] = None,
          system_name: Optional[str] = None,
          use_case: str = "evaluation",
          on_escalate: str = "allow",  # "allow" | "block"
          reasoning_from: Optional[Callable[..., str]] = None):
    """Decorator: pre-flight the wrapped function through /govern.

    The decorator turns any tool-invocation function into a governed call.
    On APPROVE the call proceeds. On BLOCK it raises BlockedByPolicy. On
    ESCALATE_HUMAN it either proceeds (`on_escalate="allow"`, useful during
    shadow mode) or raises EscalatedToHuman (`on_escalate="block"`).

    `reasoning_from(*args, **kwargs) -> str` extracts the reasoning trace
    to send to /govern. If unset, we stringify the positional args.
    """
    if on_escalate not in ("allow", "block"):
        raise ValueError("on_escalate must be 'allow' or 'block'")

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            trace = reasoning_from(*args, **kwargs) if reasoning_from else " ".join(map(str, args))
            verdict = client.govern(
                system_name=system_name or fn.__name__,
                reasoning_trace=trace,
                use_case=use_case,
            )
            if verdict.action == "BLOCK":
                raise BlockedByPolicy(verdict.raw)
            if verdict.action == "ESCALATE_HUMAN" and on_escalate == "block":
                raise EscalatedToHuman(verdict.raw)
            return fn(*args, **kwargs)
        wrapper.__governlayer_guarded__ = True  # type: ignore[attr-defined]
        return wrapper
    return decorator
