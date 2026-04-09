"""Generic REST Evidence Connector — configurable connector for any REST API.

Supports Jira, ServiceNow, Splunk, or any REST endpoint that returns JSON.
Configuration specifies base_url, auth headers, and a list of endpoints to poll.
"""

import logging
from typing import Any, Dict, List, Optional

from src.evidence.connectors import BaseConnector, ConnectorError, EvidenceResult

logger = logging.getLogger("governlayer.evidence.rest")


class GenericRESTConnector(BaseConnector):
    """Configurable connector for any JSON REST API."""

    connector_type = "rest"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "").rstrip("/")
        self.auth_header = config.get("auth_header", {})  # e.g. {"Authorization": "Bearer xxx"}
        self.extra_headers = config.get("extra_headers", {})
        self.endpoints = config.get("endpoints", [])
        # Each endpoint: {"path": "/api/v1/...", "name": "...", "evidence_type": "...",
        #                  "controls": [...], "framework": "..."}
        self.timeout = config.get("timeout", 30)
        self.verify_path = config.get("verify_path", "/")  # path for test_connection

    def _request_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "GovernLayer-Evidence/1.0",
        }
        headers.update(self.auth_header)
        headers.update(self.extra_headers)
        return headers

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def test_connection(self) -> Dict[str, Any]:
        """Test connectivity to the base URL."""
        if not self.base_url:
            return {"ok": False, "message": "base_url not configured", "details": {}}

        try:
            url = f"{self.base_url}{self.verify_path}"
            resp = self._http_request(
                url, headers=self._request_headers(), timeout=self.timeout
            )
            return {
                "ok": resp["status"] < 400,
                "message": f"Connected to {self.base_url} (HTTP {resp['status']})",
                "details": {
                    "status_code": resp["status"],
                    "url": url,
                },
            }
        except ConnectorError as exc:
            return {"ok": False, "message": str(exc), "details": exc.details}
        except Exception as exc:
            return {"ok": False, "message": f"Unexpected error: {exc}", "details": {}}

    def collect_evidence(self) -> List[EvidenceResult]:
        """Hit each configured endpoint and collect the response as evidence."""
        if not self.base_url:
            raise ConnectorError("base_url not configured", connector_type="rest")
        if not self.endpoints:
            raise ConnectorError(
                "No endpoints configured — add entries to the 'endpoints' list",
                connector_type="rest",
            )

        results: List[EvidenceResult] = []

        for ep in self.endpoints:
            path = ep.get("path", "")
            name = ep.get("name", path)
            evidence_type = ep.get("evidence_type", "api_response")
            controls = ep.get("controls", [])
            framework = ep.get("framework", "")
            method = ep.get("method", "GET").upper()

            url = f"{self.base_url}{path}"
            try:
                resp = self._http_request(
                    url,
                    method=method,
                    headers=self._request_headers(),
                    timeout=self.timeout,
                )
                body = resp["body"]

                # Try to summarize the response
                if isinstance(body, list):
                    summary = f"Returned {len(body)} items"
                elif isinstance(body, dict):
                    summary = f"Returned object with {len(body)} keys"
                else:
                    summary = f"Returned {type(body).__name__}"

                results.append(
                    EvidenceResult(
                        evidence_type=evidence_type,
                        title=f"{name}: {summary}",
                        description=f"Collected from {method} {path} (HTTP {resp['status']})",
                        raw_data={
                            "url": url,
                            "method": method,
                            "status_code": resp["status"],
                            "response": body if isinstance(body, (dict, list)) else str(body)[:5000],
                        },
                        mapped_controls=controls,
                        source=f"rest:{self.base_url}{path}",
                        framework=framework,
                    )
                )
            except ConnectorError as exc:
                logger.warning("REST endpoint %s failed: %s", url, exc)
                results.append(
                    EvidenceResult(
                        evidence_type="collection_error",
                        title=f"Failed: {name}",
                        description=str(exc),
                        raw_data={"error": str(exc), "url": url, "details": exc.details},
                        mapped_controls=controls,
                        source=f"rest:{url}",
                        framework=framework,
                    )
                )
            except Exception as exc:
                logger.warning("REST endpoint %s unexpected error: %s", url, exc)

        return results

    def collect(self) -> List[EvidenceResult]:
        """Alias for collect_evidence() for convenience."""
        return self.collect_evidence()
