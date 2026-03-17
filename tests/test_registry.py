"""Tests for Model Registry API — /v1/models CRUD + lifecycle + model cards."""

import uuid


def _unique_name():
    return f"test-model-{uuid.uuid4().hex[:8]}"


def test_register_model(client, auth_headers):
    name = _unique_name()
    r = client.post("/v1/models", json={
        "name": name,
        "version": "1.0.0",
        "provider": "OpenAI",
        "model_type": "classification",
        "risk_tier": "high",
        "description": "Test model for classification",
        "owner": "test-team@company.com",
        "tags": ["test", "classification"],
        "metadata": {"framework": "pytorch"},
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == name
    assert data["version"] == "1.0.0"
    assert data["governance_status"] == "pending"
    assert "id" in data
    assert "created_at" in data


def test_register_model_minimal(client, auth_headers):
    name = _unique_name()
    r = client.post("/v1/models", json={
        "name": name,
        "version": "0.1.0",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == name
    assert data["version"] == "0.1.0"


def test_register_model_requires_auth(client):
    r = client.post("/v1/models", json={
        "name": "unauthorized-model",
        "version": "1.0.0",
    })
    assert r.status_code in (401, 403)


def test_list_models(client, auth_headers):
    # Register two models first
    for _ in range(2):
        client.post("/v1/models", json={
            "name": _unique_name(),
            "version": "1.0.0",
        }, headers=auth_headers)

    r = client.get("/v1/models")
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "models" in data
    assert data["total"] >= 2
    assert "page" in data
    assert "limit" in data
    assert "pages" in data


def test_list_models_pagination(client, auth_headers):
    # Register enough models
    for _ in range(3):
        client.post("/v1/models", json={
            "name": _unique_name(),
            "version": "1.0.0",
        }, headers=auth_headers)

    r = client.get("/v1/models?page=1&limit=2")
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 1
    assert data["limit"] == 2
    assert len(data["models"]) <= 2


def test_list_models_filter_governance_status(client, auth_headers):
    r = client.get("/v1/models?governance_status=pending")
    assert r.status_code == 200
    data = r.json()
    for m in data["models"]:
        assert m["governance_status"] == "pending"


def test_get_model_by_id(client, auth_headers):
    name = _unique_name()
    create_resp = client.post("/v1/models", json={
        "name": name,
        "version": "2.0.0",
        "description": "Detailed test model",
        "owner": "ml-team@company.com",
    }, headers=auth_headers)
    model_id = create_resp.json()["id"]

    r = client.get(f"/v1/models/{model_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == model_id
    assert data["name"] == name
    assert data["version"] == "2.0.0"
    assert data["description"] == "Detailed test model"
    assert data["owner"] == "ml-team@company.com"


def test_get_model_not_found(client):
    r = client.get("/v1/models/999999")
    assert r.status_code == 404


def test_update_lifecycle(client, auth_headers):
    create_resp = client.post("/v1/models", json={
        "name": _unique_name(),
        "version": "1.0.0",
    }, headers=auth_headers)
    model_id = create_resp.json()["id"]

    r = client.put(f"/v1/models/{model_id}/lifecycle", json={
        "lifecycle": "staging",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["lifecycle"] == "staging"
    assert data["id"] == model_id


def test_update_lifecycle_to_production(client, auth_headers):
    create_resp = client.post("/v1/models", json={
        "name": _unique_name(),
        "version": "1.0.0",
    }, headers=auth_headers)
    model_id = create_resp.json()["id"]

    r = client.put(f"/v1/models/{model_id}/lifecycle", json={
        "lifecycle": "production",
    }, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["lifecycle"] == "production"


def test_update_lifecycle_invalid_value(client, auth_headers):
    create_resp = client.post("/v1/models", json={
        "name": _unique_name(),
        "version": "1.0.0",
    }, headers=auth_headers)
    model_id = create_resp.json()["id"]

    r = client.put(f"/v1/models/{model_id}/lifecycle", json={
        "lifecycle": "nonexistent_stage",
    }, headers=auth_headers)
    assert r.status_code == 400


def test_update_lifecycle_not_found(client, auth_headers):
    r = client.put("/v1/models/999999/lifecycle", json={
        "lifecycle": "staging",
    }, headers=auth_headers)
    assert r.status_code == 404


def test_update_lifecycle_requires_auth(client, auth_headers):
    create_resp = client.post("/v1/models", json={
        "name": _unique_name(),
        "version": "1.0.0",
    }, headers=auth_headers)
    model_id = create_resp.json()["id"]

    r = client.put(f"/v1/models/{model_id}/lifecycle", json={
        "lifecycle": "staging",
    })
    assert r.status_code in (401, 403)


def test_create_model_card(client, auth_headers):
    create_resp = client.post("/v1/models", json={
        "name": _unique_name(),
        "version": "1.0.0",
    }, headers=auth_headers)
    model_id = create_resp.json()["id"]

    r = client.post(f"/v1/models/{model_id}/card", json={
        "intended_use": "Credit risk assessment",
        "limitations": "Not suitable for high-value loans",
        "training_data_summary": "10M anonymized loan records",
        "evaluation_metrics": {"auc": 0.92, "f1": 0.87},
        "ethical_considerations": "Bias testing across demographics",
        "fairness_analysis": {"gender_parity": 0.95},
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["model_id"] == model_id
    assert data["intended_use"] == "Credit risk assessment"
    assert "id" in data


def test_create_model_card_not_found(client, auth_headers):
    r = client.post("/v1/models/999999/card", json={
        "intended_use": "Testing",
    }, headers=auth_headers)
    assert r.status_code == 404


def test_get_model_card(client, auth_headers):
    create_resp = client.post("/v1/models", json={
        "name": _unique_name(),
        "version": "1.0.0",
    }, headers=auth_headers)
    model_id = create_resp.json()["id"]

    client.post(f"/v1/models/{model_id}/card", json={
        "intended_use": "Fraud detection",
        "limitations": "Requires real-time data",
        "ethical_considerations": "Monitor for false positives",
        "evaluation_metrics": {"precision": 0.95},
        "fairness_analysis": {"age_group_parity": 0.91},
    }, headers=auth_headers)

    r = client.get(f"/v1/models/{model_id}/card")
    assert r.status_code == 200
    data = r.json()
    assert data["model_id"] == model_id
    assert data["intended_use"] == "Fraud detection"
    assert data["limitations"] == "Requires real-time data"
    assert data["evaluation_metrics"]["precision"] == 0.95
    assert data["fairness_analysis"]["age_group_parity"] == 0.91


def test_get_model_card_not_found(client):
    r = client.get("/v1/models/999999/card")
    assert r.status_code == 404
