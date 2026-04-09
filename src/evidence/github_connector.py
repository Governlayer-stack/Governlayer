"""GitHub Evidence Connector — collects compliance evidence via GitHub REST API.

Uses personal access token or GitHub App authentication. Collects:
- Repository settings (branch protection, required reviews)
- Organization audit log
- Security alerts (Dependabot)
"""

import logging
from typing import Any, Dict, List, Optional

from src.evidence.connectors import BaseConnector, ConnectorError, EvidenceResult

logger = logging.getLogger("governlayer.evidence.github")

API_BASE = "https://api.github.com"


class GitHubConnector(BaseConnector):
    """Connector for GitHub using REST API with token auth."""

    connector_type = "github"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.token = config.get("github_token", "")
        self.org = config.get("github_org", "")
        self.repos = config.get("github_repos", [])  # optional filter

    def _headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "GovernLayer-Evidence/1.0",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def test_connection(self) -> Dict[str, Any]:
        """Verify GitHub token by fetching authenticated user info."""
        if not self.token:
            return {"ok": False, "message": "GitHub token not configured", "details": {}}
        try:
            resp = self._http_request(f"{API_BASE}/user", headers=self._headers())
            body = resp["body"]
            return {
                "ok": True,
                "message": "GitHub token validated",
                "details": {
                    "login": body.get("login", "unknown"),
                    "scopes": resp["headers"].get("X-OAuth-Scopes", "unknown"),
                },
            }
        except ConnectorError as exc:
            return {"ok": False, "message": str(exc), "details": exc.details}
        except Exception as exc:
            return {"ok": False, "message": f"Unexpected error: {exc}", "details": {}}

    def collect_evidence(self) -> List[EvidenceResult]:
        """Collect evidence from GitHub APIs."""
        results: List[EvidenceResult] = []

        collectors = [
            self._collect_repo_settings,
            self._collect_audit_log,
            self._collect_security_alerts,
        ]

        for collector in collectors:
            try:
                results.extend(collector())
            except ConnectorError as exc:
                logger.warning("GitHub evidence collection partial failure: %s", exc)
                results.append(
                    EvidenceResult(
                        evidence_type="collection_error",
                        title=f"Failed: {collector.__name__}",
                        description=str(exc),
                        raw_data={"error": str(exc), "details": exc.details},
                        mapped_controls=[],
                        source="github:error",
                    )
                )
            except Exception as exc:
                logger.warning("GitHub evidence unexpected error: %s", exc)

        return results

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    def _get_org_repos(self) -> List[Dict]:
        """Fetch org repos, optionally filtered."""
        if self.repos:
            result = []
            for repo_name in self.repos:
                try:
                    resp = self._http_request(
                        f"{API_BASE}/repos/{self.org}/{repo_name}",
                        headers=self._headers(),
                    )
                    result.append(resp["body"])
                except ConnectorError:
                    logger.warning("Could not fetch repo %s/%s", self.org, repo_name)
            return result

        # Fetch all org repos
        url = f"{API_BASE}/orgs/{self.org}/repos?per_page=100&type=all"
        return self._paginate_github(url, self._headers(), max_pages=3)

    def _collect_repo_settings(self) -> List[EvidenceResult]:
        """Check branch protection and required reviews on repos."""
        if not self.org:
            raise ConnectorError("github_org not configured", connector_type="github")

        repos = self._get_org_repos()
        protected_repos = []
        unprotected_repos = []

        for repo in repos:
            repo_name = repo.get("full_name", repo.get("name", "unknown"))
            default_branch = repo.get("default_branch", "main")

            try:
                bp_resp = self._http_request(
                    f"{API_BASE}/repos/{repo_name}/branches/{default_branch}/protection",
                    headers=self._headers(),
                )
                bp = bp_resp["body"]
                protected_repos.append({
                    "repo": repo_name,
                    "branch": default_branch,
                    "required_reviews": bp.get("required_pull_request_reviews", {}).get(
                        "required_approving_review_count", 0
                    ),
                    "require_status_checks": bp.get("required_status_checks") is not None,
                    "enforce_admins": bp.get("enforce_admins", {}).get("enabled", False),
                    "allow_force_push": bp.get("allow_force_pushes", {}).get("enabled", True),
                })
            except ConnectorError:
                unprotected_repos.append({"repo": repo_name, "branch": default_branch})

        total = len(repos)
        protected_count = len(protected_repos)

        return [
            EvidenceResult(
                evidence_type="branch_protection",
                title=f"Branch protection: {protected_count}/{total} repos protected",
                description=(
                    f"{protected_count} of {total} repositories have branch protection on their default branch. "
                    f"{len(unprotected_repos)} repos lack protection."
                ),
                raw_data={
                    "total_repos": total,
                    "protected_repos": protected_repos,
                    "unprotected_repos": unprotected_repos,
                },
                mapped_controls=["SOC2-CC8.1", "ISO27001-A.14.2", "NIST-CM-3"],
                source="github:repos",
                framework="SOC2,ISO27001,NIST",
            )
        ]

    def _collect_audit_log(self) -> List[EvidenceResult]:
        """Fetch organization audit log entries (requires org admin)."""
        if not self.org:
            raise ConnectorError("github_org not configured", connector_type="github")

        try:
            url = f"{API_BASE}/orgs/{self.org}/audit-log?per_page=100&include=all"
            entries = self._paginate_github(url, self._headers(), max_pages=2)
        except ConnectorError as exc:
            # Audit log requires org admin — graceful fallback
            return [
                EvidenceResult(
                    evidence_type="audit_log",
                    title="Audit log: insufficient permissions",
                    description=(
                        "Could not access organization audit log. "
                        "Token may lack admin:org scope. "
                        f"Error: {exc}"
                    ),
                    raw_data={"error": str(exc), "requires": "admin:org scope"},
                    mapped_controls=["SOC2-CC7.2", "ISO27001-A.12.4", "NIST-AU-2"],
                    source="github:audit-log",
                    framework="SOC2,ISO27001,NIST",
                )
            ]

        # Summarize by action
        action_counts: Dict[str, int] = {}
        for entry in entries:
            action = entry.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        return [
            EvidenceResult(
                evidence_type="audit_log",
                title=f"Audit log: {len(entries)} recent events",
                description=f"Collected {len(entries)} audit log entries across {len(action_counts)} action types",
                raw_data={
                    "total_entries": len(entries),
                    "action_summary": action_counts,
                    "sample_entries": entries[:10],
                },
                mapped_controls=["SOC2-CC7.2", "ISO27001-A.12.4", "NIST-AU-2"],
                source="github:audit-log",
                framework="SOC2,ISO27001,NIST",
            )
        ]

    def _collect_security_alerts(self) -> List[EvidenceResult]:
        """Fetch Dependabot security alerts for org repos."""
        if not self.org:
            raise ConnectorError("github_org not configured", connector_type="github")

        repos = self._get_org_repos()
        all_alerts: List[Dict] = []
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        repos_with_alerts = 0

        for repo in repos:
            repo_name = repo.get("full_name", repo.get("name", "unknown"))
            try:
                resp = self._http_request(
                    f"{API_BASE}/repos/{repo_name}/dependabot/alerts?state=open&per_page=100",
                    headers=self._headers(),
                )
                alerts = resp["body"] if isinstance(resp["body"], list) else []
                if alerts:
                    repos_with_alerts += 1
                for alert in alerts:
                    severity = (
                        alert.get("security_advisory", {})
                        .get("severity", "unknown")
                        .lower()
                    )
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    all_alerts.append({
                        "repo": repo_name,
                        "package": alert.get("dependency", {}).get("package", {}).get("name"),
                        "severity": severity,
                        "summary": alert.get("security_advisory", {}).get("summary", ""),
                        "state": alert.get("state", ""),
                    })
            except ConnectorError:
                # Dependabot may not be enabled or token lacks permissions
                pass

        return [
            EvidenceResult(
                evidence_type="security_alerts",
                title=f"Dependabot: {len(all_alerts)} open alerts across {repos_with_alerts} repos",
                description=(
                    f"Found {len(all_alerts)} open Dependabot alerts: "
                    f"{severity_counts['critical']} critical, {severity_counts['high']} high, "
                    f"{severity_counts['medium']} medium, {severity_counts['low']} low"
                ),
                raw_data={
                    "total_alerts": len(all_alerts),
                    "repos_with_alerts": repos_with_alerts,
                    "severity_counts": severity_counts,
                    "alerts": all_alerts[:50],
                },
                mapped_controls=["SOC2-CC7.1", "ISO27001-A.12.6", "NIST-SI-2", "OWASP-A06"],
                source="github:dependabot",
                framework="SOC2,ISO27001,NIST,OWASP",
            )
        ]
