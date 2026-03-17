"""GRC Platform Connectors — ServiceNow, Jira, Slack webhook dispatchers."""

import hashlib
import hmac
import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, List, Optional


class BaseConnector:
    """Base class for GRC connectors."""

    def __init__(self, webhook_url: str, secret: Optional[str] = None):
        self.webhook_url = webhook_url
        self.secret = secret

    def _sign(self, payload: bytes) -> str:
        if not self.secret:
            return ""
        return hmac.new(self.secret.encode(), payload, hashlib.sha256).hexdigest()

    def _send(self, data: Dict) -> Dict:
        payload = json.dumps(data).encode()
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["X-GovernLayer-Signature"] = f"sha256={self._sign(payload)}"

        req = urllib.request.Request(self.webhook_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {"status": "sent", "code": resp.status}
        except urllib.error.HTTPError as e:
            return {"status": "error", "code": e.code, "detail": e.read().decode()[:200]}
        except Exception as e:
            return {"status": "error", "detail": str(e)}


class SlackConnector(BaseConnector):
    """Send governance alerts to Slack channels."""

    SEVERITY_EMOJI = {
        "critical": ":rotating_light:",
        "high": ":warning:",
        "medium": ":large_yellow_circle:",
        "low": ":information_source:",
        "info": ":white_check_mark:",
    }

    def send_alert(self, title: str, message: str, severity: str = "medium",
                   fields: Optional[Dict[str, str]] = None) -> Dict:
        emoji = self.SEVERITY_EMOJI.get(severity, ":bell:")
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {title}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message}
            },
        ]
        if fields:
            field_blocks = [{"type": "mrkdwn", "text": f"*{k}:*\n{v}"} for k, v in fields.items()]
            blocks.append({"type": "section", "fields": field_blocks[:10]})

        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"GovernLayer | {severity.upper()} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"}]
        })

        return self._send({"blocks": blocks})

    def send_incident(self, incident: Dict) -> Dict:
        return self.send_alert(
            title=f"Incident: {incident.get('title', 'Unknown')}",
            message=incident.get("description", "No description"),
            severity=incident.get("severity", "medium"),
            fields={
                "Status": incident.get("status", "open"),
                "Category": incident.get("category", "—"),
                "Reporter": incident.get("reporter", "system"),
            },
        )

    def send_compliance_alert(self, report: Dict) -> Dict:
        score = report.get("compliance_score", 0)
        severity = "critical" if score < 50 else "high" if score < 70 else "medium" if score < 90 else "info"
        return self.send_alert(
            title=f"Compliance Report: {report.get('system_name', 'Unknown')}",
            message=f"Framework: {report.get('report_type', 'Unknown')}\nScore: {score}%",
            severity=severity,
            fields={
                "Compliant": str(report.get("summary", {}).get("compliant", 0)),
                "Non-Compliant": str(report.get("summary", {}).get("non_compliant", 0)),
                "Recommendation": report.get("recommendation", "—"),
            },
        )


class JiraConnector(BaseConnector):
    """Create Jira tickets for governance findings."""

    SEVERITY_PRIORITY = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def __init__(self, base_url: str, email: str, api_token: str, project_key: str):
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        import base64
        self._auth = base64.b64encode(f"{email}:{api_token}".encode()).decode()

    def _send_jira(self, data: Dict) -> Dict:
        payload = json.dumps(data).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self._auth}",
        }
        url = f"{self.base_url}/rest/api/3/issue"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
                return {"status": "created", "key": result.get("key"), "id": result.get("id")}
        except urllib.error.HTTPError as e:
            return {"status": "error", "code": e.code, "detail": e.read().decode()[:200]}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def create_incident_ticket(self, incident: Dict) -> Dict:
        severity = incident.get("severity", "medium")
        return self._send_jira({
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[GovernLayer] {incident.get('title', 'AI Governance Incident')}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": incident.get("description", "No description")}]
                    }]
                },
                "issuetype": {"name": "Bug"},
                "priority": {"name": self.SEVERITY_PRIORITY.get(severity, "Medium")},
                "labels": ["ai-governance", "governlayer", severity],
            }
        })

    def create_compliance_ticket(self, report: Dict) -> Dict:
        non_compliant = report.get("summary", {}).get("non_compliant", 0)
        return self._send_jira({
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[GovernLayer] Compliance gap: {report.get('report_type', 'Unknown')} - {report.get('system_name', '')}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": f"Compliance score: {report.get('compliance_score', 0)}%. {non_compliant} non-compliant requirements found. Recommendation: {report.get('recommendation', '')}"}]
                    }]
                },
                "issuetype": {"name": "Task"},
                "priority": {"name": "High" if non_compliant > 0 else "Medium"},
                "labels": ["ai-governance", "compliance", "governlayer"],
            }
        })


class ServiceNowConnector(BaseConnector):
    """Create ServiceNow incidents and change requests for governance findings."""

    SEVERITY_IMPACT = {"critical": 1, "high": 2, "medium": 3, "low": 4}

    def __init__(self, instance_url: str, username: str, password: str):
        self.instance_url = instance_url.rstrip("/")
        import base64
        self._auth = base64.b64encode(f"{username}:{password}".encode()).decode()

    def _send_snow(self, table: str, data: Dict) -> Dict:
        payload = json.dumps(data).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self._auth}",
            "Accept": "application/json",
        }
        url = f"{self.instance_url}/api/now/table/{table}"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
                record = result.get("result", {})
                return {"status": "created", "sys_id": record.get("sys_id"), "number": record.get("number")}
        except urllib.error.HTTPError as e:
            return {"status": "error", "code": e.code, "detail": e.read().decode()[:200]}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def create_incident(self, incident: Dict) -> Dict:
        severity = incident.get("severity", "medium")
        return self._send_snow("incident", {
            "short_description": f"[GovernLayer] {incident.get('title', 'AI Governance Incident')}",
            "description": incident.get("description", ""),
            "impact": self.SEVERITY_IMPACT.get(severity, 3),
            "urgency": self.SEVERITY_IMPACT.get(severity, 3),
            "category": "AI Governance",
            "subcategory": incident.get("category", "General"),
            "assignment_group": "AI Governance Team",
        })

    def create_change_request(self, description: str, risk_level: str = "medium") -> Dict:
        return self._send_snow("change_request", {
            "short_description": f"[GovernLayer] AI Governance Change",
            "description": description,
            "type": "Standard",
            "risk": risk_level,
            "category": "AI Governance",
            "assignment_group": "AI Governance Team",
        })
