"""Tests for Incident Management API — /v1/incidents CRUD + lifecycle."""

import uuid


def _unique_title():
    return f"Incident-{uuid.uuid4().hex[:8]}"


def test_create_incident(client, auth_headers):
    title = _unique_title()
    r = client.post("/v1/incidents", json={
        "title": title,
        "description": "Bias detected in loan approval model",
        "severity": "high",
        "category": "fairness",
        "reporter": "audit-bot",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["title"] == title
    assert data["severity"] == "high"
    assert data["status"] == "open"
    assert "id" in data
    assert "created_at" in data


def test_create_incident_default_severity(client, auth_headers):
    r = client.post("/v1/incidents", json={
        "title": _unique_title(),
    }, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["severity"] == "medium"


def test_create_incident_requires_auth(client):
    r = client.post("/v1/incidents", json={
        "title": "Unauthorized incident",
        "severity": "low",
    })
    assert r.status_code in (401, 403)


def test_list_incidents(client, auth_headers):
    # Create two incidents
    for _ in range(2):
        client.post("/v1/incidents", json={
            "title": _unique_title(),
            "severity": "medium",
        }, headers=auth_headers)

    r = client.get("/v1/incidents")
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "incidents" in data
    assert data["total"] >= 2
    assert "page" in data
    assert "limit" in data
    assert "pages" in data


def test_list_incidents_pagination(client, auth_headers):
    for _ in range(3):
        client.post("/v1/incidents", json={
            "title": _unique_title(),
        }, headers=auth_headers)

    r = client.get("/v1/incidents?page=1&limit=2")
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 1
    assert data["limit"] == 2
    assert len(data["incidents"]) <= 2


def test_list_incidents_filter_severity(client, auth_headers):
    client.post("/v1/incidents", json={
        "title": _unique_title(),
        "severity": "critical",
    }, headers=auth_headers)

    r = client.get("/v1/incidents?severity=critical")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    for i in data["incidents"]:
        assert i["severity"] == "critical"


def test_get_incident_by_id(client, auth_headers):
    title = _unique_title()
    create_resp = client.post("/v1/incidents", json={
        "title": title,
        "description": "Detailed incident for testing",
        "severity": "high",
        "category": "data_drift",
        "reporter": "ml-ops",
    }, headers=auth_headers)
    incident_id = create_resp.json()["id"]

    r = client.get(f"/v1/incidents/{incident_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == incident_id
    assert data["title"] == title
    assert data["description"] == "Detailed incident for testing"
    assert data["severity"] == "high"
    assert data["status"] == "open"
    assert data["category"] == "data_drift"
    assert data["reporter"] == "ml-ops"
    assert data["timeline"] is not None
    assert len(data["timeline"]) >= 1


def test_get_incident_not_found(client):
    r = client.get("/v1/incidents/999999")
    assert r.status_code == 404


def test_update_incident_status(client, auth_headers):
    create_resp = client.post("/v1/incidents", json={
        "title": _unique_title(),
        "severity": "high",
    }, headers=auth_headers)
    incident_id = create_resp.json()["id"]

    r = client.patch(f"/v1/incidents/{incident_id}", json={
        "status": "investigating",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "investigating"
    assert "updated_at" in data


def test_update_incident_severity(client, auth_headers):
    create_resp = client.post("/v1/incidents", json={
        "title": _unique_title(),
        "severity": "medium",
    }, headers=auth_headers)
    incident_id = create_resp.json()["id"]

    r = client.patch(f"/v1/incidents/{incident_id}", json={
        "severity": "critical",
    }, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["severity"] == "critical"


def test_update_incident_assignee(client, auth_headers):
    create_resp = client.post("/v1/incidents", json={
        "title": _unique_title(),
    }, headers=auth_headers)
    incident_id = create_resp.json()["id"]

    r = client.patch(f"/v1/incidents/{incident_id}", json={
        "assignee": "responder@company.com",
    }, headers=auth_headers)
    assert r.status_code == 200


def test_update_incident_resolve(client, auth_headers):
    create_resp = client.post("/v1/incidents", json={
        "title": _unique_title(),
        "severity": "high",
    }, headers=auth_headers)
    incident_id = create_resp.json()["id"]

    r = client.patch(f"/v1/incidents/{incident_id}", json={
        "status": "resolved",
        "resolution": "Retrained model with balanced dataset",
        "root_cause": "Training data bias",
    }, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"

    # Verify resolved_at is set
    detail = client.get(f"/v1/incidents/{incident_id}").json()
    assert detail["resolved_at"] is not None
    assert detail["resolution"] == "Retrained model with balanced dataset"
    assert detail["root_cause"] == "Training data bias"


def test_update_incident_invalid_status(client, auth_headers):
    create_resp = client.post("/v1/incidents", json={
        "title": _unique_title(),
    }, headers=auth_headers)
    incident_id = create_resp.json()["id"]

    r = client.patch(f"/v1/incidents/{incident_id}", json={
        "status": "nonexistent_status",
    }, headers=auth_headers)
    assert r.status_code == 400


def test_update_incident_not_found(client, auth_headers):
    r = client.patch("/v1/incidents/999999", json={
        "status": "investigating",
    }, headers=auth_headers)
    assert r.status_code == 404


def test_update_incident_requires_auth(client, auth_headers):
    create_resp = client.post("/v1/incidents", json={
        "title": _unique_title(),
    }, headers=auth_headers)
    incident_id = create_resp.json()["id"]

    r = client.patch(f"/v1/incidents/{incident_id}", json={
        "status": "investigating",
    })
    assert r.status_code in (401, 403)
