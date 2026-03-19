"""GovernLayer SDK — main client.

Thread-safe HTTP client with automatic retry, exponential backoff, and
typed response models for every GovernLayer API endpoint.

Usage::

    from governlayer import GovernLayer

    gl = GovernLayer(api_key="gl_your_key")
    decision = gl.govern(system_name="loan-scorer", reasoning_trace="Approved loan for user 42")
    print(decision.governance_action)  # "APPROVE"
"""

from __future__ import annotations

import time
import threading
from typing import Any, Dict, List, Optional, Type, TypeVar

import requests
from pydantic import BaseModel

from governlayer.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    GovernLayerError,
    NotFoundError,
    RateLimitError,
    ServerError,
    TimeoutError,
    ValidationError,
)
from governlayer.models import (
    Agent,
    AgentGovernanceResult,
    AgentListResponse,
    AuditHistoryResponse,
    AuditResult,
    ComplianceDeadlines,
    ComplianceSummary,
    DriftResult,
    FrameworkListResponse,
    GovernanceDecision,
    HealthStatus,
    Incident,
    IncidentListResponse,
    IncidentResponsePlan,
    IncidentUpdateResult,
    JurisdictionMap,
    LedgerResponse,
    LedgerVerification,
    LifecycleResult,
    ModelListResponse,
    PipelineResult,
    Policy,
    PolicyEvaluationResult,
    PolicyListResponse,
    RegisteredModel,
    ReportResult,
    RiskScore,
    ScanResult,
    ServiceHealth,
    ShadowScanResult,
    ThreatAnalysis,
    UsageSummary,
    UsageTrends,
)

__all__ = ["GovernLayer"]

T = TypeVar("T", bound=BaseModel)

_DEFAULT_BASE_URL = "https://api.governlayer.ai"
_DEFAULT_TIMEOUT = 30.0
_MAX_RETRIES = 3
_BACKOFF_FACTOR = 0.5  # seconds
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class GovernLayer:
    """GovernLayer API client.

    Args:
        api_key: API key (``gl_xxx``) or JWT token for authentication.
        base_url: Base URL of the GovernLayer API.  Defaults to
            ``https://api.governlayer.ai``.
        timeout: Request timeout in seconds.  Defaults to 30.
        max_retries: Maximum number of retries for transient failures.
            Defaults to 3.
        session: Optional :class:`requests.Session` instance for connection
            pooling or custom transport adapters.

    Example::

        gl = GovernLayer(api_key="gl_live_abc123")
        decision = gl.govern(
            system_name="loan-scorer",
            reasoning_trace="Approved loan based on credit history",
        )
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = _MAX_RETRIES,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key must not be empty")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._session = session or requests.Session()
        self._lock = threading.Lock()

        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "governlayer-python/0.1.0",
            }
        )

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _handle_error(self, response: requests.Response) -> None:
        """Raise a typed exception for non-2xx responses."""
        status = response.status_code
        try:
            body = response.json()
        except Exception:
            body = {"detail": response.text}

        message = body.get("detail", body.get("error", response.text))
        if isinstance(message, list):
            # FastAPI validation errors come as a list
            message = "; ".join(
                f"{e.get('loc', ['?'])[-1]}: {e.get('msg', '?')}" for e in message
            )

        if status == 401:
            raise AuthenticationError(message, status, body)
        if status == 403:
            raise AuthorizationError(message, status, body)
        if status == 404:
            raise NotFoundError(message, status, body)
        if status == 422:
            raise ValidationError(message, status, body)
        if status == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                message,
                status,
                body,
                retry_after=float(retry_after) if retry_after else None,
            )
        if 500 <= status < 600:
            raise ServerError(message, status, body)
        raise GovernLayerError(message, status, body)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute an HTTP request with retry + exponential backoff.

        Thread-safe: a lock serialises retry-loop bookkeeping while the
        actual HTTP call runs without holding the lock.
        """
        url = self._url(path)
        last_exception: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                resp = self._session.request(
                    method,
                    url,
                    json=json,
                    params=self._clean_params(params),
                    timeout=self._timeout,
                )

                if resp.status_code < 300:
                    return resp.json()

                # Retry on transient failures
                if resp.status_code in _RETRYABLE_STATUS_CODES and attempt < self._max_retries:
                    wait = _BACKOFF_FACTOR * (2 ** attempt)
                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        if retry_after:
                            wait = max(wait, float(retry_after))
                    time.sleep(wait)
                    continue

                self._handle_error(resp)

            except requests.ConnectionError as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    time.sleep(_BACKOFF_FACTOR * (2 ** attempt))
                    continue
                raise ConnectionError(
                    f"Failed to connect to {url}: {exc}"
                ) from exc

            except requests.Timeout as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    time.sleep(_BACKOFF_FACTOR * (2 ** attempt))
                    continue
                raise TimeoutError(
                    f"Request to {url} timed out after {self._timeout}s"
                ) from exc

            except (GovernLayerError, requests.RequestException):
                raise

            except Exception as exc:
                raise GovernLayerError(f"Unexpected error: {exc}") from exc

        # Should not reach here, but just in case
        raise GovernLayerError(
            f"Request failed after {self._max_retries + 1} attempts",
        )

    @staticmethod
    def _clean_params(params: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Remove ``None`` values so they are not sent as query params."""
        if params is None:
            return None
        return {k: v for k, v in params.items() if v is not None}

    def _get(self, path: str, *, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("GET", path, params=params)

    def _post(self, path: str, *, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("POST", path, json=json)

    def _put(self, path: str, *, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("PUT", path, json=json)

    def _patch(self, path: str, *, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("PATCH", path, json=json)

    def _delete(self, path: str, *, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("DELETE", path, params=params)

    def _parse(self, model: Type[T], data: Dict[str, Any]) -> T:
        """Parse a dict into a Pydantic model, tolerating extra fields."""
        return model.model_validate(data)

    # ==================================================================
    # Health
    # ==================================================================

    def health(self) -> HealthStatus:
        """Check API health.

        Returns:
            HealthStatus with ``status``, ``version``, and ``database`` fields.
        """
        return self._parse(HealthStatus, self._get("/health"))

    def service_health(self) -> ServiceHealth:
        """Full service health check (database, Redis, Ollama, n8n).

        Returns:
            ServiceHealth with per-service status breakdown.
        """
        return self._parse(ServiceHealth, self._get("/automate/health"))

    # ==================================================================
    # Governance
    # ==================================================================

    def govern(
        self,
        system_name: str,
        reasoning_trace: str,
        *,
        use_case: str = "general",
        ai_decision: Optional[str] = None,
        handles_personal_data: bool = False,
        makes_autonomous_decisions: bool = False,
        used_in_critical_infrastructure: bool = False,
        has_human_oversight: bool = True,
        is_explainable: bool = True,
        has_bias_testing: bool = False,
    ) -> GovernanceDecision:
        """Run the full governance decision pipeline.

        Performs drift detection, risk scoring, and issues a governance
        action (APPROVE, ESCALATE_HUMAN, or BLOCK) recorded in the
        immutable audit ledger.

        Args:
            system_name: Identifier for the AI system being governed.
            reasoning_trace: The AI system's reasoning output to evaluate.
            use_case: Domain context (e.g. ``"finance"``, ``"healthcare"``).
            ai_decision: Optional description of the AI's decision.
            handles_personal_data: Whether the system processes PII.
            makes_autonomous_decisions: Whether decisions are made without human input.
            used_in_critical_infrastructure: Whether the system operates in critical infra.
            has_human_oversight: Whether a human reviews outputs.
            is_explainable: Whether the system provides explanations.
            has_bias_testing: Whether bias testing has been performed.

        Returns:
            GovernanceDecision with action, risk score, drift analysis, and ledger hash.
        """
        payload: Dict[str, Any] = {
            "system_name": system_name,
            "reasoning_trace": reasoning_trace,
            "use_case": use_case,
            "handles_personal_data": handles_personal_data,
            "makes_autonomous_decisions": makes_autonomous_decisions,
            "used_in_critical_infrastructure": used_in_critical_infrastructure,
            "has_human_oversight": has_human_oversight,
            "is_explainable": is_explainable,
            "has_bias_testing": has_bias_testing,
        }
        if ai_decision is not None:
            payload["ai_decision"] = ai_decision
        return self._parse(GovernanceDecision, self._post("/govern", json=payload))

    def scan(
        self,
        system_name: str,
        reasoning_trace: str,
        *,
        use_case: str = "general",
        handles_personal_data: bool = False,
        makes_autonomous_decisions: bool = False,
        used_in_critical_infrastructure: bool = False,
        has_human_oversight: bool = True,
        is_explainable: bool = True,
        has_bias_testing: bool = False,
    ) -> ScanResult:
        """Quick deterministic scan (drift + risk only, no LLM calls).

        Faster and cheaper than :meth:`govern` — ideal for high-volume
        real-time checks.

        Args:
            system_name: Identifier for the AI system.
            reasoning_trace: The AI system's reasoning output to evaluate.
            use_case: Domain context.
            handles_personal_data: Whether the system processes PII.
            makes_autonomous_decisions: Whether decisions are autonomous.
            used_in_critical_infrastructure: Whether used in critical infra.
            has_human_oversight: Whether a human reviews outputs.
            is_explainable: Whether explanations are provided.
            has_bias_testing: Whether bias testing has been performed.

        Returns:
            ScanResult with action, risk score, and drift coefficient.
        """
        payload: Dict[str, Any] = {
            "system_name": system_name,
            "reasoning_trace": reasoning_trace,
            "use_case": use_case,
            "handles_personal_data": handles_personal_data,
            "makes_autonomous_decisions": makes_autonomous_decisions,
            "used_in_critical_infrastructure": used_in_critical_infrastructure,
            "has_human_oversight": has_human_oversight,
            "is_explainable": is_explainable,
            "has_bias_testing": has_bias_testing,
        }
        return self._parse(ScanResult, self._post("/automate/scan", json=payload))

    def full_pipeline(
        self,
        system_name: str,
        reasoning_trace: str,
        *,
        use_case: str = "general",
        handles_personal_data: bool = False,
        makes_autonomous_decisions: bool = False,
        used_in_critical_infrastructure: bool = False,
        has_human_oversight: bool = True,
        is_explainable: bool = True,
        has_bias_testing: bool = False,
        system_description: str = "",
        industry: str = "technology",
        frameworks: str = "NIST_AI_RMF,EU_AI_ACT,ISO_42001",
        run_audit: bool = True,
        run_threats: bool = False,
    ) -> PipelineResult:
        """Run the complete governance pipeline in a single call.

        Executes drift detection, risk scoring, governance decision,
        optional compliance audit (LLM), optional threat analysis, and
        records everything in the immutable ledger.

        Args:
            system_name: Identifier for the AI system.
            reasoning_trace: The AI system's reasoning output.
            use_case: Domain context.
            handles_personal_data: Whether the system processes PII.
            makes_autonomous_decisions: Whether decisions are autonomous.
            used_in_critical_infrastructure: Whether used in critical infra.
            has_human_oversight: Whether a human reviews outputs.
            is_explainable: Whether explanations are provided.
            has_bias_testing: Whether bias testing has been performed.
            system_description: Free-text description of the system.
            industry: Industry sector.
            frameworks: Comma-separated compliance frameworks.
            run_audit: Whether to run the LLM compliance audit stage.
            run_threats: Whether to run the LLM threat analysis stage.

        Returns:
            PipelineResult with all stage results, audit report, and ledger hash.
        """
        payload: Dict[str, Any] = {
            "system_name": system_name,
            "reasoning_trace": reasoning_trace,
            "use_case": use_case,
            "handles_personal_data": handles_personal_data,
            "makes_autonomous_decisions": makes_autonomous_decisions,
            "used_in_critical_infrastructure": used_in_critical_infrastructure,
            "has_human_oversight": has_human_oversight,
            "is_explainable": is_explainable,
            "has_bias_testing": has_bias_testing,
            "system_description": system_description,
            "industry": industry,
            "frameworks": frameworks,
            "run_audit": run_audit,
            "run_threats": run_threats,
        }
        return self._parse(PipelineResult, self._post("/automate/full-pipeline", json=payload))

    # ==================================================================
    # Drift Detection
    # ==================================================================

    def detect_drift(
        self,
        reasoning_trace: str,
        *,
        use_case: str = "general",
        threshold: float = 0.3,
    ) -> DriftResult:
        """Detect behavioral drift in an AI system's reasoning.

        Uses sentence-transformer embeddings (or keyword fallback) to
        calculate a drift coefficient against safety manifolds.

        Args:
            reasoning_trace: The AI system's reasoning output.
            use_case: Domain context for manifold selection.
            threshold: Drift coefficient threshold for vetoing (0.0 to 1.0).

        Returns:
            DriftResult with drift coefficient, veto status, and explanation.
        """
        payload = {
            "reasoning_trace": reasoning_trace,
            "use_case": use_case,
            "threshold": threshold,
        }
        return self._parse(DriftResult, self._post("/drift", json=payload))

    # ==================================================================
    # Risk Scoring
    # ==================================================================

    def score_risk(
        self,
        system_name: str,
        *,
        handles_personal_data: bool = False,
        makes_autonomous_decisions: bool = False,
        used_in_critical_infrastructure: bool = False,
        has_human_oversight: bool = True,
        is_explainable: bool = True,
        has_bias_testing: bool = False,
    ) -> RiskScore:
        """Compute a deterministic 6-dimension risk score.

        No LLM calls — instant results. Dimensions: Privacy, Autonomy,
        Infrastructure, Oversight, Transparency, Fairness.

        Args:
            system_name: Identifier for the AI system.
            handles_personal_data: Whether the system processes PII.
            makes_autonomous_decisions: Whether decisions are autonomous.
            used_in_critical_infrastructure: Whether used in critical infra.
            has_human_oversight: Whether a human reviews outputs.
            is_explainable: Whether explanations are provided.
            has_bias_testing: Whether bias testing has been performed.

        Returns:
            RiskScore with overall score, risk level, and dimension breakdown.
        """
        payload = {
            "system_name": system_name,
            "handles_personal_data": handles_personal_data,
            "makes_autonomous_decisions": makes_autonomous_decisions,
            "used_in_critical_infrastructure": used_in_critical_infrastructure,
            "has_human_oversight": has_human_oversight,
            "is_explainable": is_explainable,
            "has_bias_testing": has_bias_testing,
        }
        return self._parse(RiskScore, self._post("/risk-score", json=payload))

    # ==================================================================
    # Audit
    # ==================================================================

    def audit(
        self,
        system_name: str,
        system_description: str,
        industry: str,
        frameworks: str,
    ) -> AuditResult:
        """Run an LLM-powered compliance audit.

        An LLM auditor evaluates the system against the specified
        regulatory frameworks and produces a detailed report.

        Args:
            system_name: Identifier for the AI system.
            system_description: Description of the system's purpose and behavior.
            industry: Industry sector (e.g. ``"finance"``, ``"healthcare"``).
            frameworks: Comma-separated framework list
                (e.g. ``"EU_AI_ACT,NIST_AI_RMF"``).

        Returns:
            AuditResult with LLM-generated findings and ledger hash.
        """
        payload = {
            "system_name": system_name,
            "system_description": system_description,
            "industry": industry,
            "frameworks": frameworks,
        }
        return self._parse(AuditResult, self._post("/audit", json=payload))

    def audit_history(
        self,
        *,
        page: int = 1,
        per_page: int = 50,
    ) -> AuditHistoryResponse:
        """Retrieve paginated audit history for the authenticated user.

        Args:
            page: Page number (1-indexed).
            per_page: Results per page (max 200).

        Returns:
            AuditHistoryResponse with paginated audit entries.
        """
        params = {"page": page, "per_page": per_page}
        return self._parse(AuditHistoryResponse, self._get("/audit-history", params=params))

    # ==================================================================
    # Reports
    # ==================================================================

    def generate_report(
        self,
        system_name: str,
        *,
        framework: str = "eu_ai_act",
        risk_tier: str = "high",
        context: Optional[Dict[str, Any]] = None,
    ) -> ReportResult:
        """Generate a regulatory compliance report for a specific framework.

        Supports 18 frameworks including EU AI Act, NIST AI RMF, ISO 42001,
        SOC 2, GDPR, HIPAA, and more.

        Args:
            system_name: Identifier for the AI system.
            framework: Framework ID (e.g. ``"eu_ai_act"``, ``"nist_ai_rmf"``).
            risk_tier: Risk classification (``"low"``, ``"medium"``, ``"high"``).
            context: Optional additional context for report generation.

        Returns:
            ReportResult with compliance score and framework-specific findings.
        """
        payload: Dict[str, Any] = {
            "system_name": system_name,
            "framework": framework,
            "risk_tier": risk_tier,
        }
        if context:
            payload["context"] = context
        return self._parse(ReportResult, self._post("/v1/reports", json=payload))

    def compliance_summary(
        self,
        *,
        system_name: str = "organization",
    ) -> ComplianceSummary:
        """Get a quick compliance score summary across key frameworks.

        Args:
            system_name: System to evaluate (defaults to ``"organization"``).

        Returns:
            ComplianceSummary with per-framework scores and average.
        """
        params = {"system_name": system_name}
        return self._parse(ComplianceSummary, self._get("/v1/reports/compliance-summary", params=params))

    def list_frameworks(self) -> FrameworkListResponse:
        """List all 18 supported regulatory frameworks.

        Returns:
            FrameworkListResponse with framework details including
            jurisdiction and description.
        """
        return self._parse(FrameworkListResponse, self._get("/v1/reports/frameworks"))

    # ==================================================================
    # Agent Registry
    # ==================================================================

    def list_agents(
        self,
        *,
        status: Optional[str] = None,
        agent_type: Optional[str] = None,
        is_shadow: Optional[bool] = None,
        team: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> AgentListResponse:
        """List all registered AI agents with optional filters.

        Args:
            status: Filter by status (``"approved"``, ``"under_review"``, etc.).
            agent_type: Filter by type (``"autonomous"``, ``"chatbot"``, etc.).
            is_shadow: Filter for shadow AI (``True``) or registered (``False``).
            team: Filter by team name.
            page: Page number (1-indexed).
            limit: Results per page (max 50).

        Returns:
            AgentListResponse with paginated agent list and summary counts.
        """
        params: Dict[str, Any] = {
            "status": status,
            "agent_type": agent_type,
            "is_shadow": is_shadow,
            "team": team,
            "page": page,
            "limit": limit,
        }
        return self._parse(AgentListResponse, self._get("/v1/agents", params=params))

    def get_agent(self, agent_id: int) -> Agent:
        """Get detailed agent information including agent card.

        Args:
            agent_id: Numeric ID of the agent.

        Returns:
            Agent with full details.

        Raises:
            NotFoundError: If the agent does not exist.
        """
        return self._parse(Agent, self._get(f"/v1/agents/{agent_id}"))

    def register_agent(
        self,
        name: str,
        *,
        agent_type: str = "autonomous",
        description: Optional[str] = None,
        owner: Optional[str] = None,
        team: Optional[str] = None,
        purpose: Optional[str] = None,
        tools: Optional[List[str]] = None,
        data_sources: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        guardrails: Optional[List[str]] = None,
        autonomy_level: int = 1,
        model_provider: Optional[str] = None,
        model_name: Optional[str] = None,
        risk_tier: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Agent:
        """Register a new AI agent in the governance registry.

        Args:
            name: Unique agent name.
            agent_type: Agent type (``"autonomous"``, ``"chatbot"``,
                ``"tool_agent"``, ``"copilot"``).
            description: Free-text description.
            owner: Owner email or identifier.
            team: Owning team name.
            purpose: Agent's purpose statement.
            tools: List of tools the agent uses.
            data_sources: Data sources the agent accesses.
            permissions: Granted permissions.
            guardrails: Applied guardrails.
            autonomy_level: Autonomy level (1-5).
            model_provider: LLM provider name.
            model_name: Model identifier.
            risk_tier: Risk classification.
            tags: Searchable tags.
            metadata: Arbitrary key-value metadata.

        Returns:
            Agent with the newly created record.
        """
        payload: Dict[str, Any] = {"name": name, "agent_type": agent_type}
        if description is not None:
            payload["description"] = description
        if owner is not None:
            payload["owner"] = owner
        if team is not None:
            payload["team"] = team
        if purpose is not None:
            payload["purpose"] = purpose
        if tools is not None:
            payload["tools"] = tools
        if data_sources is not None:
            payload["data_sources"] = data_sources
        if permissions is not None:
            payload["permissions"] = permissions
        if guardrails is not None:
            payload["guardrails"] = guardrails
        payload["autonomy_level"] = autonomy_level
        if model_provider is not None:
            payload["model_provider"] = model_provider
        if model_name is not None:
            payload["model_name"] = model_name
        if risk_tier is not None:
            payload["risk_tier"] = risk_tier
        if tags is not None:
            payload["tags"] = tags
        if metadata is not None:
            payload["metadata"] = metadata
        return self._parse(Agent, self._post("/v1/agents", json=payload))

    def govern_agent(
        self,
        agent_id: int,
        action: str,
        *,
        approved_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> AgentGovernanceResult:
        """Approve, reject, suspend, or activate an agent.

        Args:
            agent_id: Numeric ID of the agent.
            action: Governance action — one of ``"approve"``, ``"reject"``,
                ``"suspend"``, ``"activate"``, ``"review"``.
            approved_by: Identity of the approver (optional).
            reason: Reason for the governance action (optional).

        Returns:
            AgentGovernanceResult with updated status.

        Raises:
            NotFoundError: If the agent does not exist.
        """
        payload: Dict[str, Any] = {"action": action}
        if approved_by is not None:
            payload["approved_by"] = approved_by
        if reason is not None:
            payload["reason"] = reason
        return self._parse(
            AgentGovernanceResult,
            self._post(f"/v1/agents/{agent_id}/governance", json=payload),
        )

    def scan_shadow_ai(
        self,
        targets: List[str],
        *,
        scan_type: str = "api_patterns",
    ) -> ShadowScanResult:
        """Scan for unauthorized/unregistered AI usage (Shadow AI detection).

        Checks provided network targets against known AI provider API
        patterns to detect ungoverned AI usage.

        Args:
            targets: List of URLs, hostnames, or API endpoints to scan.
            scan_type: Type of scan (default ``"api_patterns"``).

        Returns:
            ShadowScanResult with detection details and risk level.
        """
        payload = {"targets": targets, "scan_type": scan_type}
        return self._parse(ShadowScanResult, self._post("/v1/agents/discovery/scan", json=payload))

    # ==================================================================
    # Model Registry
    # ==================================================================

    def list_models(
        self,
        *,
        lifecycle: Optional[str] = None,
        governance_status: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> ModelListResponse:
        """List all registered AI/ML models with optional filters.

        Args:
            lifecycle: Filter by lifecycle stage (``"development"``,
                ``"staging"``, ``"production"``, ``"deprecated"``,
                ``"archived"``).
            governance_status: Filter by governance status.
            page: Page number (1-indexed).
            limit: Results per page.

        Returns:
            ModelListResponse with paginated model list.
        """
        params: Dict[str, Any] = {
            "lifecycle": lifecycle,
            "governance_status": governance_status,
            "page": page,
            "limit": limit,
        }
        return self._parse(ModelListResponse, self._get("/v1/models", params=params))

    def get_model(self, model_id: int) -> RegisteredModel:
        """Get detailed model information.

        Args:
            model_id: Numeric ID of the model.

        Returns:
            RegisteredModel with full details.

        Raises:
            NotFoundError: If the model does not exist.
        """
        return self._parse(RegisteredModel, self._get(f"/v1/models/{model_id}"))

    def register_model(
        self,
        name: str,
        version: str,
        *,
        provider: Optional[str] = None,
        model_type: Optional[str] = None,
        risk_tier: Optional[str] = None,
        description: Optional[str] = None,
        owner: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RegisteredModel:
        """Register a new AI/ML model in the governance registry.

        Args:
            name: Model name (e.g. ``"gpt-4-fine-tuned"``).
            version: Semantic version (e.g. ``"1.0.0"``).
            provider: Provider name (e.g. ``"openai"``, ``"internal"``).
            model_type: Model type (e.g. ``"classifier"``, ``"llm"``).
            risk_tier: Risk classification.
            description: Free-text description.
            owner: Owner email or identifier.
            tags: Searchable tags.
            metadata: Arbitrary key-value metadata.

        Returns:
            RegisteredModel with the newly created record.
        """
        payload: Dict[str, Any] = {"name": name, "version": version}
        if provider is not None:
            payload["provider"] = provider
        if model_type is not None:
            payload["model_type"] = model_type
        if risk_tier is not None:
            payload["risk_tier"] = risk_tier
        if description is not None:
            payload["description"] = description
        if owner is not None:
            payload["owner"] = owner
        if tags is not None:
            payload["tags"] = tags
        if metadata is not None:
            payload["metadata"] = metadata
        return self._parse(RegisteredModel, self._post("/v1/models", json=payload))

    def update_lifecycle(
        self,
        model_id: int,
        lifecycle: str,
    ) -> LifecycleResult:
        """Promote or demote a model through lifecycle stages.

        Args:
            model_id: Numeric ID of the model.
            lifecycle: Target lifecycle stage — one of ``"development"``,
                ``"staging"``, ``"production"``, ``"deprecated"``,
                ``"archived"``.

        Returns:
            LifecycleResult with updated lifecycle state.

        Raises:
            NotFoundError: If the model does not exist.
        """
        payload = {"lifecycle": lifecycle}
        return self._parse(
            LifecycleResult,
            self._put(f"/v1/models/{model_id}/lifecycle", json=payload),
        )

    # ==================================================================
    # Incidents
    # ==================================================================

    def list_incidents(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> IncidentListResponse:
        """List all governance incidents with optional filters.

        Args:
            status: Filter by status (``"open"``, ``"investigating"``,
                ``"resolved"``, ``"closed"``).
            severity: Filter by severity (``"low"``, ``"medium"``,
                ``"high"``, ``"critical"``).
            page: Page number (1-indexed).
            limit: Results per page.

        Returns:
            IncidentListResponse with paginated incident list.
        """
        params: Dict[str, Any] = {
            "status": status,
            "severity": severity,
            "page": page,
            "limit": limit,
        }
        return self._parse(IncidentListResponse, self._get("/v1/incidents", params=params))

    def get_incident(self, incident_id: int) -> Incident:
        """Get detailed incident information.

        Args:
            incident_id: Numeric ID of the incident.

        Returns:
            Incident with full details including timeline.

        Raises:
            NotFoundError: If the incident does not exist.
        """
        return self._parse(Incident, self._get(f"/v1/incidents/{incident_id}"))

    def create_incident(
        self,
        title: str,
        *,
        severity: str = "medium",
        description: Optional[str] = None,
        model_id: Optional[int] = None,
        category: Optional[str] = None,
        reporter: Optional[str] = None,
    ) -> Incident:
        """Report a new AI governance incident.

        Args:
            title: Short incident title.
            severity: Severity level — ``"low"``, ``"medium"``, ``"high"``,
                or ``"critical"``.
            description: Detailed incident description.
            model_id: Related model ID (optional).
            category: Incident category (e.g. ``"data_drift"``,
                ``"fairness"``, ``"performance"``).
            reporter: Reporter identity (optional, defaults to auth identity).

        Returns:
            Incident with the newly created record.
        """
        payload: Dict[str, Any] = {"title": title, "severity": severity}
        if description is not None:
            payload["description"] = description
        if model_id is not None:
            payload["model_id"] = model_id
        if category is not None:
            payload["category"] = category
        if reporter is not None:
            payload["reporter"] = reporter
        return self._parse(Incident, self._post("/v1/incidents", json=payload))

    def update_incident(
        self,
        incident_id: int,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assignee: Optional[str] = None,
        root_cause: Optional[str] = None,
        resolution: Optional[str] = None,
        impact: Optional[str] = None,
    ) -> IncidentUpdateResult:
        """Update incident status, assignment, or resolution.

        Args:
            incident_id: Numeric ID of the incident.
            status: New status (``"open"``, ``"investigating"``,
                ``"mitigated"``, ``"resolved"``, ``"closed"``).
            severity: Updated severity level.
            assignee: Person assigned to the incident.
            root_cause: Root cause analysis.
            resolution: Resolution details.
            impact: Impact assessment.

        Returns:
            IncidentUpdateResult with updated status.

        Raises:
            NotFoundError: If the incident does not exist.
        """
        payload: Dict[str, Any] = {}
        if status is not None:
            payload["status"] = status
        if severity is not None:
            payload["severity"] = severity
        if assignee is not None:
            payload["assignee"] = assignee
        if root_cause is not None:
            payload["root_cause"] = root_cause
        if resolution is not None:
            payload["resolution"] = resolution
        if impact is not None:
            payload["impact"] = impact
        return self._parse(
            IncidentUpdateResult,
            self._patch(f"/v1/incidents/{incident_id}", json=payload),
        )

    # ==================================================================
    # Policies
    # ==================================================================

    def list_policies(self, *, active_only: bool = True) -> PolicyListResponse:
        """List all governance policies.

        Args:
            active_only: If ``True``, only return active policies.

        Returns:
            PolicyListResponse with policy list.
        """
        params = {"active_only": active_only}
        return self._parse(PolicyListResponse, self._get("/v1/policies", params=params))

    def get_policy(self, policy_id: int) -> Policy:
        """Get a specific policy with all rules.

        Args:
            policy_id: Numeric ID of the policy.

        Returns:
            Policy with full rule definitions.

        Raises:
            NotFoundError: If the policy does not exist.
        """
        return self._parse(Policy, self._get(f"/v1/policies/{policy_id}"))

    def create_policy(
        self,
        name: str,
        *,
        rules: Optional[List[Dict[str, Any]]] = None,
        description: Optional[str] = None,
        version: str = "1.0",
        created_by: Optional[str] = None,
    ) -> Policy:
        """Create a new governance policy.

        Args:
            name: Policy name.
            rules: List of rule definitions. Each rule is a dict with
                ``name``, ``condition``, ``action``, and ``message`` keys.
            description: Policy description.
            version: Semantic version.
            created_by: Creator identity.

        Returns:
            Policy with the newly created record.
        """
        payload: Dict[str, Any] = {"name": name, "version": version}
        if rules is not None:
            payload["rules"] = rules
        if description is not None:
            payload["description"] = description
        if created_by is not None:
            payload["created_by"] = created_by
        return self._parse(Policy, self._post("/v1/policies", json=payload))

    def evaluate_policy(
        self,
        context: Dict[str, Any],
        *,
        policy_id: Optional[int] = None,
    ) -> PolicyEvaluationResult:
        """Evaluate context against a policy.

        Args:
            context: Dictionary of context values to evaluate against
                policy rules (e.g. ``{"risk_score": 45, "drift_coefficient": 0.2}``).
            policy_id: Specific policy to evaluate against. If ``None``,
                the default policy is used.

        Returns:
            PolicyEvaluationResult with per-rule results.
        """
        payload: Dict[str, Any] = {"context": context}
        if policy_id is not None:
            payload["policy_id"] = policy_id
        return self._parse(PolicyEvaluationResult, self._post("/v1/policies/evaluate", json=payload))

    def deactivate_policy(self, policy_id: int) -> Policy:
        """Deactivate a policy (soft delete).

        Args:
            policy_id: Numeric ID of the policy to deactivate.

        Returns:
            Policy with ``is_active=False``.

        Raises:
            NotFoundError: If the policy does not exist.
        """
        return self._parse(Policy, self._delete(f"/v1/policies/{policy_id}"))

    # ==================================================================
    # Threats
    # ==================================================================

    def analyze_threats(
        self,
        system_type: str,
        *,
        deployment_context: str = "production",
    ) -> ThreatAnalysis:
        """Analyze AI-specific threats using MITRE ATLAS and OWASP.

        Uses web search and LLM analysis to identify threats relevant
        to the given system type and deployment context.

        Args:
            system_type: Type of AI system (e.g. ``"chatbot"``,
                ``"recommendation_engine"``).
            deployment_context: Deployment environment (default ``"production"``).

        Returns:
            ThreatAnalysis with identified threats and controls.
        """
        payload = {
            "system_type": system_type,
            "deployment_context": deployment_context,
        }
        return self._parse(ThreatAnalysis, self._post("/threats", json=payload))

    def incident_response(
        self,
        incident_type: str,
        system_name: str,
        affected_users: int,
        industry: str,
    ) -> IncidentResponsePlan:
        """Generate an AI incident response plan.

        Args:
            incident_type: Type of incident (e.g. ``"data_breach"``,
                ``"bias_detected"``).
            system_name: Affected system name.
            affected_users: Number of affected users.
            industry: Industry sector.

        Returns:
            IncidentResponsePlan with LLM-generated response plan.
        """
        payload = {
            "incident_type": incident_type,
            "system_name": system_name,
            "affected_users": affected_users,
            "industry": industry,
        }
        return self._parse(IncidentResponsePlan, self._post("/incident-response", json=payload))

    def jurisdiction_map(
        self,
        countries: str,
        industry: str,
        ai_system_type: str,
    ) -> JurisdictionMap:
        """Map AI regulations by jurisdiction.

        Args:
            countries: Comma-separated country list.
            industry: Industry sector.
            ai_system_type: Type of AI system.

        Returns:
            JurisdictionMap with regulatory requirements per country.
        """
        payload = {
            "countries": countries,
            "industry": industry,
            "ai_system_type": ai_system_type,
        }
        return self._parse(JurisdictionMap, self._post("/jurisdiction", json=payload))

    def compliance_deadlines(self, *, region: str = "global") -> ComplianceDeadlines:
        """Get upcoming AI compliance deadlines.

        Args:
            region: Region filter (default ``"global"``).

        Returns:
            ComplianceDeadlines with upcoming regulatory deadlines.
        """
        params = {"region": region}
        return self._parse(ComplianceDeadlines, self._get("/deadlines", params=params))

    # ==================================================================
    # Analytics / Usage
    # ==================================================================

    def usage_summary(self, *, days: int = 30) -> UsageSummary:
        """Get high-level API usage summary.

        Args:
            days: Lookback period in days (1-365).

        Returns:
            UsageSummary with request counts, error rates, and latency.
        """
        params = {"days": days}
        return self._parse(UsageSummary, self._get("/v1/analytics/usage/summary", params=params))

    def usage_trends(
        self,
        *,
        days: int = 30,
        granularity: str = "day",
    ) -> UsageTrends:
        """Get API usage trends over time.

        Args:
            days: Lookback period in days (1-365).
            granularity: Time bucket size — ``"hour"``, ``"day"``, or ``"week"``.

        Returns:
            UsageTrends with time-series data points.
        """
        params = {"days": days, "granularity": granularity}
        return self._parse(UsageTrends, self._get("/v1/analytics/usage/trends", params=params))

    # ==================================================================
    # Ledger
    # ==================================================================

    def get_ledger(
        self,
        *,
        page: int = 1,
        per_page: int = 50,
    ) -> LedgerResponse:
        """View the immutable hash-chained audit ledger.

        Each entry is cryptographically linked to its predecessor via
        SHA-256 hashing, providing tamper-evident audit trails.

        Args:
            page: Page number (1-indexed).
            per_page: Results per page (max 200).

        Returns:
            LedgerResponse with paginated ledger entries.
        """
        params = {"page": page, "per_page": per_page}
        return self._parse(LedgerResponse, self._get("/ledger", params=params))

    def verify_ledger(self) -> LedgerVerification:
        """Verify the integrity of the hash-chained audit ledger.

        Checks that every record's ``previous_hash`` matches the
        preceding record's ``current_hash``.

        Returns:
            LedgerVerification indicating whether the chain is intact
            and listing any broken links.
        """
        return self._parse(LedgerVerification, self._get("/ledger/verify"))

    # ==================================================================
    # Utilities
    # ==================================================================

    def close(self) -> None:
        """Close the underlying HTTP session.

        Call this when you are done using the client to release
        connection pool resources.
        """
        self._session.close()

    def __enter__(self) -> "GovernLayer":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"GovernLayer(base_url={self._base_url!r})"
