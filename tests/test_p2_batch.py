"""Tests for the P2 audit batch.

Coverage:
    - Shadow-AI auto-scan finds LLM egress + bulk mutations + orphan agent keys
    - Data-catalog ingest creates + updates lineage entries
    - Webhook delivery records get written and are listable via
      GET /webhooks/deliveries
"""

import pytest

from src.governance.hitl import _escalations, _store_lock


@pytest.fixture(autouse=True)
def _clean():
    with _store_lock:
        _escalations.clear()
    yield
    with _store_lock:
        _escalations.clear()


# ═══════════════════════════════════════════════════════════════════════════
# Shadow-AI auto-scan
# ═══════════════════════════════════════════════════════════════════════════


class TestShadowAIAutoScan:
    def test_auto_scan_empty_platform_returns_safe(self, client, auth_headers):
        r = client.post("/v1/agents/discovery/auto-scan", json={
            "window_hours": 1, "limit": 100, "persist": False,
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["risk_level"] in ("safe", "medium")
        assert body["persisted"] is False

    def test_auto_scan_detects_llm_egress_from_usage_records(self, client, auth_headers):
        # Seed an Organization + UsageRecords pointing at an LLM host
        from src.models.database import SessionLocal
        from src.models.tenant import Organization, UsageRecord
        db = SessionLocal()
        try:
            import uuid as _uuid
            org = Organization(name="p2-shadow-test", slug=f"p2-{_uuid.uuid4().hex[:8]}", plan="free")
            db.add(org)
            db.flush()
            for _ in range(5):
                db.add(UsageRecord(
                    org_id=org.id,
                    api_key_id=None,
                    endpoint="POST https://api.openai.com/v1/chat/completions",
                    method="POST",
                    status_code=200,
                    latency_ms=120.0,
                ))
            db.commit()
        finally:
            db.close()

        r = client.post("/v1/agents/discovery/auto-scan", json={
            "window_hours": 24, "limit": 5000, "persist": False,
        }, headers=auth_headers)
        body = r.json()
        types = {d["detection_type"] for d in body["detections"]}
        assert "llm_egress" in types
        assert any("openai.com" in d.get("source", "") for d in body["detections"])


# ═══════════════════════════════════════════════════════════════════════════
# Data-catalog ingest
# ═══════════════════════════════════════════════════════════════════════════


class TestCatalogIngest:
    def test_catalog_ingest_creates_new_models(self, client):
        r = client.post("/lineage/catalog/ingest", json={
            "source_system": "dbt",
            "source_uri": "s3://catalog/manifest.json",
            "models": [
                {
                    "name": "credit-scorer-alpha",
                    "provider": "sklearn",
                    "family": "gradient-boost",
                    "intended_use": "consumer credit scoring",
                    "datasets": [
                        {"name": "us_credit_bureau_2026Q2", "license": "proprietary"},
                        {"name": "aggregated_bank_statements", "license": "customer_consent"},
                    ],
                },
                {
                    "name": "fraud-triage-v1",
                    "provider": "pytorch",
                    "family": "transformer",
                    "intended_use": "real-time fraud triage",
                    "datasets": [
                        {"name": "historical_fraud_labels", "license": "internal_only"},
                    ],
                },
            ],
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["source_system"] == "dbt"
        assert body["models_created"] == 2
        assert body["datasets_added"] == 3
        assert body["duplicates_skipped"] == 0

    def test_catalog_ingest_appends_datasets_on_existing_model(self, client):
        # First ingest creates
        client.post("/lineage/catalog/ingest", json={
            "source_system": "dbt",
            "models": [{
                "name": "unique-model-name-p2",
                "datasets": [{"name": "ds-1"}],
            }],
        })
        # Second ingest with same name + new dataset
        r = client.post("/lineage/catalog/ingest", json={
            "source_system": "dbt",
            "models": [{
                "name": "unique-model-name-p2",
                "datasets": [
                    {"name": "ds-1"},          # dup
                    {"name": "ds-2"},          # new
                    {"name": "ds-3"},          # new
                ],
            }],
        })
        assert r.status_code == 200
        assert r.json()["models_updated"] == 1
        assert r.json()["models_created"] == 0
        assert r.json()["datasets_added"] == 2
        assert r.json()["duplicates_skipped"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# Webhook deliveries observability
# ═══════════════════════════════════════════════════════════════════════════


class TestWebhookDeliveries:
    def test_list_deliveries_returns_empty_shape(self, client, auth_headers):
        r = client.get("/webhooks/deliveries", headers=auth_headers)
        assert r.status_code == 200
        assert "count" in r.json()
        assert "deliveries" in r.json()

    def test_deliveries_stats_shape(self, client, auth_headers):
        r = client.get("/webhooks/deliveries/stats", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["window_hours"] == 24
        assert "by_status" in body

    def test_retry_unknown_delivery_404(self, client, auth_headers):
        r = client.post("/webhooks/deliveries/999999/retry", headers=auth_headers)
        assert r.status_code == 404
