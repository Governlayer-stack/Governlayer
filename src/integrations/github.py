"""GitHub integration — automated evidence collection for compliance controls.

Connects via GitHub App or Personal Access Token to pull:
- Branch protection rules (CC8.1 Change Management)
- PR review requirements (CC8.2 Deployment Controls)
- Secret scanning status (CC6.3 Credential Management)
- Dependabot alerts (CC7.1 Vulnerability Management)
- Actions/workflows (CC8.2 CI/CD controls)
- Access permissions (CC6.1 Access Controls)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("governlayer.integrations.github")

GITHUB_API = "https://api.github.com"

# Control mapping: GitHub evidence → compliance controls
CONTROL_MAP = {
    "branch_protection": ["CC8.1", "CC8.2", "A.14.2"],
    "pr_reviews": ["CC8.1", "CC8.2"],
    "secret_scanning": ["CC6.3", "CC6.7"],
    "dependabot": ["CC7.1", "CC7.3"],
    "actions": ["CC8.2"],
    "access": ["CC6.1", "CC5.1", "CC5.2"],
    "mfa": ["CC6.1", "CC6.3"],
}

FRAMEWORK_MAP = {
    "branch_protection": ["SOC_2", "ISO_27001"],
    "pr_reviews": ["SOC_2", "ISO_27001"],
    "secret_scanning": ["SOC_2", "ISO_27001", "PCI_DSS"],
    "dependabot": ["SOC_2", "NIST_CSF"],
    "actions": ["SOC_2"],
    "access": ["SOC_2", "ISO_27001", "HIPAA"],
    "mfa": ["SOC_2", "ISO_27001", "NIST_CSF"],
}


class GitHubConnector:
    """Pull compliance evidence from GitHub repositories."""

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._client = httpx.Client(headers=self.headers, timeout=15)

    def close(self):
        self._client.close()

    def _get(self, path: str) -> Optional[Any]:
        try:
            resp = self._client.get(f"{GITHUB_API}{path}")
            if resp.status_code == 200:
                return resp.json()
            logger.warning("GitHub API %s returned %d", path, resp.status_code)
            return None
        except Exception as e:
            logger.error("GitHub API error for %s: %s", path, e)
            return None

    def test_connection(self) -> Dict:
        """Verify the token works and return the authenticated user."""
        user = self._get("/user")
        if not user:
            return {"connected": False, "error": "Invalid token or API error"}
        return {
            "connected": True,
            "user": user.get("login"),
            "name": user.get("name"),
            "scopes": user.get("plan", {}).get("name", "unknown"),
        }

    def list_repos(self, org: str = "") -> List[Dict]:
        """List repositories for the authenticated user or an org."""
        if org:
            repos = self._get(f"/orgs/{org}/repos?per_page=100&sort=updated")
        else:
            repos = self._get("/user/repos?per_page=100&sort=updated&affiliation=owner,organization_member")
        if not repos:
            return []
        return [{"name": r["full_name"], "private": r["private"], "default_branch": r["default_branch"]} for r in repos]

    def collect_evidence(self, repo: str) -> Dict:
        """Collect all compliance evidence for a repository.

        Args:
            repo: Full repo name like "owner/repo"

        Returns:
            Dict with evidence items, each mapped to controls and frameworks.
        """
        evidence = {}
        evidence["branch_protection"] = self._check_branch_protection(repo)
        evidence["pr_reviews"] = self._check_pr_reviews(repo)
        evidence["secret_scanning"] = self._check_secret_scanning(repo)
        evidence["dependabot"] = self._check_dependabot(repo)
        evidence["actions"] = self._check_actions(repo)
        evidence["access"] = self._check_access(repo)

        # Build structured evidence items
        items = []
        for key, result in evidence.items():
            items.append({
                "source": "github",
                "category": key,
                "repo": repo,
                "status": result.get("status", "unknown"),
                "details": result,
                "controls": CONTROL_MAP.get(key, []),
                "frameworks": FRAMEWORK_MAP.get(key, []),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })

        passing = sum(1 for i in items if i["status"] == "pass")
        total = len(items)

        return {
            "repo": repo,
            "evidence_items": items,
            "summary": {
                "passing": passing,
                "failing": total - passing,
                "total": total,
                "score": round(passing / total * 100) if total else 0,
            },
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

    def _check_branch_protection(self, repo: str) -> Dict:
        """Check if default branch has protection rules."""
        repo_info = self._get(f"/repos/{repo}")
        if not repo_info:
            return {"status": "error", "message": "Cannot access repo"}

        branch = repo_info.get("default_branch", "main")
        protection = self._get(f"/repos/{repo}/branches/{branch}/protection")

        if not protection:
            return {
                "status": "fail",
                "branch": branch,
                "message": "No branch protection rules on default branch",
                "remediation": "Enable branch protection: require PR reviews, status checks, and restrict force pushes",
            }

        rules = {
            "require_pr_reviews": bool(protection.get("required_pull_request_reviews")),
            "require_status_checks": bool(protection.get("required_status_checks")),
            "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False),
            "restrict_pushes": bool(protection.get("restrictions")),
            "require_signatures": protection.get("required_signatures", {}).get("enabled", False),
            "require_linear_history": protection.get("required_linear_history", {}).get("enabled", False),
        }

        passing_rules = sum(1 for v in rules.values() if v)
        status = "pass" if passing_rules >= 3 else "warning" if passing_rules >= 1 else "fail"

        return {
            "status": status,
            "branch": branch,
            "rules": rules,
            "passing_rules": passing_rules,
            "total_rules": len(rules),
        }

    def _check_pr_reviews(self, repo: str) -> Dict:
        """Check recent PRs for review compliance."""
        prs = self._get(f"/repos/{repo}/pulls?state=closed&per_page=20&sort=updated&direction=desc")
        if not prs:
            return {"status": "warning", "message": "No recent PRs found"}

        reviewed = 0
        total = 0
        for pr in prs[:20]:
            if pr.get("merged_at"):
                total += 1
                reviews = self._get(f"/repos/{repo}/pulls/{pr['number']}/reviews")
                if reviews and any(r["state"] == "APPROVED" for r in reviews):
                    reviewed += 1

        if total == 0:
            return {"status": "warning", "message": "No merged PRs in recent history"}

        pct = round(reviewed / total * 100)
        return {
            "status": "pass" if pct >= 80 else "warning" if pct >= 50 else "fail",
            "reviewed": reviewed,
            "total_merged": total,
            "review_rate": pct,
            "message": f"{pct}% of merged PRs had approved reviews",
        }

    def _check_secret_scanning(self, repo: str) -> Dict:
        """Check if secret scanning is enabled and for any alerts."""
        repo_info = self._get(f"/repos/{repo}")
        if not repo_info:
            return {"status": "error", "message": "Cannot access repo"}

        security = repo_info.get("security_and_analysis", {})
        secret_scanning = security.get("secret_scanning", {}).get("status", "disabled")
        push_protection = security.get("secret_scanning_push_protection", {}).get("status", "disabled")

        alerts = self._get(f"/repos/{repo}/secret-scanning/alerts?per_page=5&state=open")
        open_alerts = len(alerts) if alerts else 0

        enabled = secret_scanning == "enabled"
        return {
            "status": "pass" if enabled and open_alerts == 0 else "warning" if enabled else "fail",
            "secret_scanning_enabled": enabled,
            "push_protection_enabled": push_protection == "enabled",
            "open_alerts": open_alerts,
            "message": f"Secret scanning {'enabled' if enabled else 'disabled'}, {open_alerts} open alerts",
        }

    def _check_dependabot(self, repo: str) -> Dict:
        """Check Dependabot alerts for vulnerabilities."""
        alerts = self._get(f"/repos/{repo}/dependabot/alerts?per_page=50&state=open")

        if alerts is None:
            return {"status": "warning", "message": "Dependabot not enabled or no access"}

        critical = sum(1 for a in alerts if a.get("security_advisory", {}).get("severity") == "critical")
        high = sum(1 for a in alerts if a.get("security_advisory", {}).get("severity") == "high")

        status = "fail" if critical > 0 else "warning" if high > 0 else "pass" if len(alerts) <= 5 else "warning"
        return {
            "status": status,
            "total_open": len(alerts),
            "critical": critical,
            "high": high,
            "message": f"{len(alerts)} open alerts ({critical} critical, {high} high)",
        }

    def _check_actions(self, repo: str) -> Dict:
        """Check if CI/CD workflows exist and are running."""
        workflows = self._get(f"/repos/{repo}/actions/workflows")
        if not workflows or workflows.get("total_count", 0) == 0:
            return {"status": "warning", "message": "No GitHub Actions workflows found"}

        active = [w for w in workflows.get("workflows", []) if w.get("state") == "active"]
        runs = self._get(f"/repos/{repo}/actions/runs?per_page=5")
        recent_runs = len(runs.get("workflow_runs", [])) if runs else 0

        return {
            "status": "pass" if active and recent_runs > 0 else "warning",
            "total_workflows": workflows.get("total_count", 0),
            "active_workflows": len(active),
            "recent_runs": recent_runs,
            "workflow_names": [w["name"] for w in active[:5]],
        }

    def _check_access(self, repo: str) -> Dict:
        """Check repository access and collaborator count."""
        collaborators = self._get(f"/repos/{repo}/collaborators?per_page=100")
        if collaborators is None:
            return {"status": "warning", "message": "Cannot check collaborators (may need admin access)"}

        admins = [c for c in collaborators if c.get("permissions", {}).get("admin")]
        writers = [c for c in collaborators if c.get("permissions", {}).get("push") and not c.get("permissions", {}).get("admin")]

        return {
            "status": "pass" if len(admins) <= 5 else "warning",
            "total_collaborators": len(collaborators),
            "admins": len(admins),
            "writers": len(writers),
            "admin_logins": [a["login"] for a in admins[:10]],
            "message": f"{len(collaborators)} collaborators ({len(admins)} admins)",
        }
