"""Tests for Report Generation API — /v1/reports for 18 regulatory frameworks."""


REPORT_FRAMEWORKS = [
    "eu_ai_act", "nist_ai_rmf", "iso_42001", "iso_27001", "nis2", "dora",
    "ccpa", "hipaa", "mitre_atlas", "owasp_ai", "nist_csf", "oecd_ai",
    "ieee_ethics", "hitrust", "nyc_ll144", "colorado_sb169", "soc2", "gdpr",
]


def test_generate_eu_ai_act_report(client):
    r = client.post("/v1/reports", json={
        "system_name": "loan-scorer",
        "framework": "eu_ai_act",
        "risk_tier": "high",
        "context": {
            "risk_score": 45,
            "has_model_card": True,
            "has_explanation": True,
            "human_oversight": True,
            "drift_score": 0.15,
        },
    })
    assert r.status_code == 200
    data = r.json()
    assert data["report_type"] == "EU AI Act Compliance"
    assert data["system_name"] == "loan-scorer"
    assert data["risk_tier"] == "high"
    assert "compliance_score" in data
    assert "requirements" in data
    assert "summary" in data
    assert "generated_at" in data


def test_generate_iso_27001_report(client):
    r = client.post("/v1/reports", json={
        "system_name": "data-pipeline",
        "framework": "iso_27001",
        "context": {"has_encryption": True},
    })
    assert r.status_code == 200
    data = r.json()
    assert data["system_name"] == "data-pipeline"
    assert "generated_at" in data


def test_generate_nis2_report(client):
    r = client.post("/v1/reports", json={
        "system_name": "critical-infra-ai",
        "framework": "nis2",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["system_name"] == "critical-infra-ai"


def test_generate_dora_report(client):
    r = client.post("/v1/reports", json={
        "system_name": "trading-ai",
        "framework": "dora",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["system_name"] == "trading-ai"


def test_generate_nist_csf_report(client):
    r = client.post("/v1/reports", json={
        "system_name": "security-monitor",
        "framework": "nist_csf",
        "context": {"has_incident_response": True},
    })
    assert r.status_code == 200
    data = r.json()
    assert data["system_name"] == "security-monitor"


def test_generate_owasp_ai_report(client):
    r = client.post("/v1/reports", json={
        "system_name": "web-ai-app",
        "framework": "owasp_ai",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["system_name"] == "web-ai-app"


def test_generate_report_all_frameworks(client):
    """Verify all 18 frameworks produce valid reports."""
    for fw in REPORT_FRAMEWORKS:
        r = client.post("/v1/reports", json={
            "system_name": "test-system",
            "framework": fw,
        })
        assert r.status_code == 200, f"Framework {fw} failed with status {r.status_code}"
        data = r.json()
        assert "error" not in data, f"Framework {fw} returned error: {data}"
        assert data["system_name"] == "test-system", f"Framework {fw} missing system_name"


def test_generate_report_with_context(client):
    r = client.post("/v1/reports", json={
        "system_name": "governed-model",
        "framework": "eu_ai_act",
        "risk_tier": "high",
        "context": {
            "risk_score": 30,
            "has_policy": True,
            "has_model_card": True,
            "has_explanation": True,
            "human_oversight": True,
            "drift_score": 0.1,
            "pii_detected": False,
        },
    })
    assert r.status_code == 200
    data = r.json()
    # With all good context, compliance score should be high
    assert data["compliance_score"] > 50


def test_generate_report_unknown_framework(client):
    r = client.post("/v1/reports", json={
        "system_name": "test-system",
        "framework": "nonexistent_framework",
    })
    assert r.status_code == 200
    data = r.json()
    assert "error" in data
    assert "available" in data
    assert len(data["available"]) == 18


def test_list_report_frameworks(client):
    r = client.get("/v1/reports/frameworks")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 18
    assert len(data["frameworks"]) == 18

    # Verify key fields in each framework
    for fw in data["frameworks"]:
        assert "id" in fw
        assert "name" in fw
        assert "jurisdiction" in fw
        assert "description" in fw

    # Verify specific frameworks are present
    framework_ids = [fw["id"] for fw in data["frameworks"]]
    assert "eu_ai_act" in framework_ids
    assert "nist_ai_rmf" in framework_ids
    assert "gdpr" in framework_ids
    assert "soc2" in framework_ids
    assert "hipaa" in framework_ids


def test_report_default_framework(client):
    """Without specifying a framework, should default to eu_ai_act."""
    r = client.post("/v1/reports", json={
        "system_name": "default-test",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["report_type"] == "EU AI Act Compliance"
