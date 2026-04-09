"""Base connector framework for evidence collection.

Each connector implements test_connection() and collect_evidence() to gather
structured compliance evidence from external services. Evidence is persisted
to the database via EvidenceItem records.
"""

import json
import logging
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("governlayer.evidence")


class ConnectorError(Exception):
    """Raised when a connector operation fails."""

    def __init__(self, message: str, connector_type: str, details: Optional[Dict] = None):
        super().__init__(message)
        self.connector_type = connector_type
        self.details = details or {}


class EvidenceResult:
    """Structured result from a single evidence collection action."""

    def __init__(
        self,
        evidence_type: str,
        title: str,
        description: str,
        raw_data: Dict[str, Any],
        mapped_controls: List[str],
        source: str,
        framework: str = "",
    ):
        self.evidence_type = evidence_type
        self.title = title
        self.description = description
        self.raw_data = raw_data
        self.mapped_controls = mapped_controls
        self.source = source
        self.framework = framework
        self.collected_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "title": self.title,
            "description": self.description,
            "raw_data": self.raw_data,
            "mapped_controls": self.mapped_controls,
            "source": self.source,
            "framework": self.framework,
            "collected_at": self.collected_at.isoformat(),
        }


class BaseConnector(ABC):
    """Abstract base class for all evidence connectors.

    Subclasses must implement:
        connector_type: str class attribute identifying this connector
        test_connection() -> bool
        collect_evidence() -> list[EvidenceResult]
    """

    connector_type: str = "base"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._validated = False

    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Validate that the connector can reach the external service.

        Returns a dict with at least:
            {"ok": True/False, "message": "...", "details": {...}}
        """
        ...

    @abstractmethod
    def collect_evidence(self) -> List[EvidenceResult]:
        """Collect evidence from the external service.

        Returns a list of EvidenceResult objects ready for persistence.
        """
        ...

    # ------------------------------------------------------------------
    # HTTP helpers (urllib — no external deps)
    # ------------------------------------------------------------------

    def _http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Make an HTTP request and return parsed JSON response.

        Returns {"status": int, "body": parsed_json_or_str, "headers": dict}.
        Raises ConnectorError on network / parse failure.
        """
        req = urllib.request.Request(url, method=method, headers=headers or {}, data=body)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                try:
                    parsed = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    parsed = raw.decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "body": parsed,
                    "headers": dict(resp.headers),
                }
        except urllib.error.HTTPError as exc:
            raw_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise ConnectorError(
                f"HTTP {exc.code} from {url}: {raw_body[:500]}",
                connector_type=self.connector_type,
                details={"status": exc.code, "url": url, "response": raw_body[:2000]},
            ) from exc
        except urllib.error.URLError as exc:
            raise ConnectorError(
                f"Connection failed to {url}: {exc.reason}",
                connector_type=self.connector_type,
                details={"url": url, "reason": str(exc.reason)},
            ) from exc

    def _paginate_github(
        self, url: str, headers: Dict[str, str], max_pages: int = 5
    ) -> List[Any]:
        """Follow GitHub Link header pagination up to max_pages."""
        results: List[Any] = []
        current_url: Optional[str] = url
        page = 0
        while current_url and page < max_pages:
            resp = self._http_request(current_url, headers=headers)
            body = resp["body"]
            if isinstance(body, list):
                results.extend(body)
            else:
                results.append(body)
            # Parse Link header for next page
            link_header = resp["headers"].get("Link", "")
            current_url = None
            for part in link_header.split(","):
                if 'rel="next"' in part:
                    current_url = part.split(";")[0].strip().strip("<>")
            page += 1
        return results


def get_connector(connector_type: str, config: Dict[str, Any]) -> BaseConnector:
    """Factory function to instantiate a connector by type string."""
    from src.evidence.aws_connector import AWSConnector
    from src.evidence.github_connector import GitHubConnector
    from src.evidence.rest_connector import GenericRESTConnector

    registry: Dict[str, type] = {
        "aws": AWSConnector,
        "github": GitHubConnector,
        "rest": GenericRESTConnector,
    }
    cls = registry.get(connector_type)
    if not cls:
        raise ConnectorError(
            f"Unknown connector type: {connector_type}",
            connector_type=connector_type,
            details={"available": list(registry.keys())},
        )
    return cls(config)
