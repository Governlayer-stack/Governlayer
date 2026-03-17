"""GovernLayer API client — zero external dependencies."""

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from governlayer.exceptions import APIError, AuthError


class GovernLayer:
    """GovernLayer API client.

    Usage:
        gl = GovernLayer(api_key="gl_xxxxx", base_url="https://api.governlayer.ai")
        result = gl.govern(system_name="my-model", use_case="classification")
    """

    def __init__(self, api_key: str, base_url: str = "https://api.governlayer.ai"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, data: Optional[Dict] = None) -> Dict:
        url = f"{self.base_url}{path}"
        body = json.dumps(data).encode() if data else None

        req = urllib.request.Request(url, data=body, headers=self._headers, method=method)

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode() if e.fp else ""
            if e.code == 401:
                raise AuthError(f"Authentication failed: {body_text}")
            if e.code == 403:
                raise AuthError(f"Forbidden: {body_text}")
            try:
                detail = json.loads(body_text)
            except (json.JSONDecodeError, ValueError):
                detail = {"detail": body_text}
            raise APIError(f"API error {e.code}: {body_text}", status_code=e.code, response=detail)
        except urllib.error.URLError as e:
            raise APIError(f"Connection failed: {e.reason}")

    # --- Core Governance ---

    def govern(self, system_name: str, use_case: str, **kwargs) -> Dict:
        """Run full governance pipeline."""
        return self._request("POST", "/v1/govern", {"system_name": system_name, "use_case": use_case, **kwargs})

    def risk_score(self, **kwargs) -> Dict:
        """Calculate deterministic risk score."""
        return self._request("POST", "/v1/risk", kwargs)

    def scan(self, system_name: str, use_case: str) -> Dict:
        """Quick deterministic scan (no LLM)."""
        return self._request("POST", "/v1/scan", {"system_name": system_name, "use_case": use_case})

    def drift(self, reasoning_trace: str, use_case: str, threshold: float = 0.3) -> Dict:
        """Detect behavioral drift."""
        return self._request("POST", "/v1/drift", {
            "reasoning_trace": reasoning_trace, "use_case": use_case, "threshold": threshold,
        })

    # --- Analytics ---

    def test_fairness(self, predictions: List[int], labels: List[int],
                      protected_attribute: List[int], group_names: Optional[Dict] = None) -> Dict:
        """Run bias & fairness analysis."""
        payload: Dict[str, Any] = {"predictions": predictions, "labels": labels, "protected_attribute": protected_attribute}
        if group_names:
            payload["group_names"] = group_names
        return self._request("POST", "/v1/analytics/fairness", payload)

    def explain(self, feature_names: List[str], feature_values: List[float],
                prediction: str, weights: Optional[List[float]] = None) -> Dict:
        """Generate explainable AI report."""
        payload: Dict[str, Any] = {"feature_names": feature_names, "feature_values": feature_values, "prediction": prediction}
        if weights:
            payload["weights"] = weights
        return self._request("POST", "/v1/analytics/explain", payload)

    def detect_data_drift(self, reference_data: Dict[str, List[float]],
                          current_data: Dict[str, List[float]]) -> Dict:
        """Detect distribution drift."""
        return self._request("POST", "/v1/analytics/data-drift", {
            "reference_data": reference_data, "current_data": current_data,
        })

    def security_scan(self, text: str, redact: bool = False) -> Dict:
        """Scan text for prompt injection and PII."""
        return self._request("POST", "/v1/analytics/security-scan", {"text": text, "redact": redact})

    # --- Model Registry ---

    def register_model(self, name: str, version: str, **kwargs) -> Dict:
        """Register an AI model."""
        return self._request("POST", "/v1/models", {"name": name, "version": version, **kwargs})

    def get_model(self, model_id: int) -> Dict:
        return self._request("GET", f"/v1/models/{model_id}")

    def list_models(self, **kwargs) -> Dict:
        params = "&".join(f"{k}={v}" for k, v in kwargs.items() if v is not None)
        path = f"/v1/models?{params}" if params else "/v1/models"
        return self._request("GET", path)

    def promote_model(self, model_id: int, lifecycle: str) -> Dict:
        return self._request("PUT", f"/v1/models/{model_id}/lifecycle", {"lifecycle": lifecycle})

    # --- Reports ---

    def generate_report(self, system_name: str, framework: str = "eu_ai_act", **kwargs) -> Dict:
        return self._request("POST", "/v1/reports", {"system_name": system_name, "framework": framework, **kwargs})

    # --- Policies ---

    def evaluate_policy(self, context: Dict[str, Any], policy_id: Optional[int] = None) -> Dict:
        payload: Dict[str, Any] = {"context": context}
        if policy_id:
            payload["policy_id"] = policy_id
        return self._request("POST", "/v1/policies/evaluate", payload)

    # --- Incidents ---

    def create_incident(self, title: str, **kwargs) -> Dict:
        return self._request("POST", "/v1/incidents", {"title": title, **kwargs})

    def list_incidents(self, **kwargs) -> Dict:
        params = "&".join(f"{k}={v}" for k, v in kwargs.items() if v is not None)
        path = f"/v1/incidents?{params}" if params else "/v1/incidents"
        return self._request("GET", path)

    # --- Dashboard ---

    def dashboard(self) -> Dict:
        """Get organization dashboard healthcheck."""
        return self._request("GET", "/v1/dashboard")

    # --- Utility ---

    def status(self) -> Dict:
        return self._request("GET", "/api")

    def frameworks(self) -> Dict:
        return self._request("GET", "/frameworks")
