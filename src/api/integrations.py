"""GRC Integrations API — connect GovernLayer to ServiceNow, Jira, Slack."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.integrations.connectors import SlackConnector, JiraConnector, ServiceNowConnector
from src.security.auth import verify_token

router = APIRouter(prefix="/v1/integrations", tags=["Integrations"])


class SlackConfig(BaseModel):
    webhook_url: str
    title: str
    message: str
    severity: str = "medium"
    fields: Optional[Dict[str, str]] = None


class JiraConfig(BaseModel):
    base_url: str
    email: str
    api_token: str
    project_key: str
    title: str
    description: str
    severity: str = "medium"
    issue_type: str = "incident"  # incident, compliance


class ServiceNowConfig(BaseModel):
    instance_url: str
    username: str
    password: str
    title: str
    description: str
    severity: str = "medium"
    record_type: str = "incident"  # incident, change_request


class WebhookTest(BaseModel):
    url: str
    payload: Dict[str, Any] = Field(default_factory=dict)


@router.post("/slack/send")
def send_slack_alert(data: SlackConfig, current_user: str = Depends(verify_token)):
    """Send a governance alert to Slack."""
    connector = SlackConnector(webhook_url=data.webhook_url)
    result = connector.send_alert(
        title=data.title,
        message=data.message,
        severity=data.severity,
        fields=data.fields,
    )
    return {"integration": "slack", **result}


@router.post("/jira/create")
def create_jira_ticket(data: JiraConfig, current_user: str = Depends(verify_token)):
    """Create a Jira ticket for a governance finding."""
    connector = JiraConnector(
        base_url=data.base_url,
        email=data.email,
        api_token=data.api_token,
        project_key=data.project_key,
    )
    if data.issue_type == "compliance":
        result = connector.create_compliance_ticket({
            "report_type": data.title,
            "system_name": "",
            "compliance_score": 0,
            "summary": {"non_compliant": 1},
            "recommendation": data.description,
        })
    else:
        result = connector.create_incident_ticket({
            "title": data.title,
            "description": data.description,
            "severity": data.severity,
        })
    return {"integration": "jira", **result}


@router.post("/servicenow/create")
def create_servicenow_record(data: ServiceNowConfig, current_user: str = Depends(verify_token)):
    """Create a ServiceNow incident or change request."""
    connector = ServiceNowConnector(
        instance_url=data.instance_url,
        username=data.username,
        password=data.password,
    )
    if data.record_type == "change_request":
        result = connector.create_change_request(
            description=data.description,
            risk_level=data.severity,
        )
    else:
        result = connector.create_incident({
            "title": data.title,
            "description": data.description,
            "severity": data.severity,
        })
    return {"integration": "servicenow", **result}


@router.get("/available")
def list_available_integrations(current_user: str = Depends(verify_token)):
    """List all available GRC integrations."""
    return {
        "integrations": [
            {
                "id": "slack",
                "name": "Slack",
                "type": "alerting",
                "description": "Send governance alerts, incident notifications, and compliance reports to Slack channels",
                "auth": "webhook_url",
                "capabilities": ["alerts", "incidents", "compliance_reports"],
            },
            {
                "id": "jira",
                "name": "Jira",
                "type": "ticketing",
                "description": "Create Jira tickets for governance incidents, compliance gaps, and remediation tasks",
                "auth": "email + api_token",
                "capabilities": ["incident_tickets", "compliance_tickets", "task_tracking"],
            },
            {
                "id": "servicenow",
                "name": "ServiceNow",
                "type": "itsm",
                "description": "Create ServiceNow incidents and change requests for AI governance findings",
                "auth": "username + password",
                "capabilities": ["incidents", "change_requests"],
            },
            {
                "id": "webhook",
                "name": "Custom Webhook",
                "type": "generic",
                "description": "Send governance events to any webhook endpoint with HMAC-SHA256 signing",
                "auth": "webhook_url + optional secret",
                "capabilities": ["any_event"],
            },
        ],
    }
