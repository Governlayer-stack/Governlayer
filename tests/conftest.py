import os
import pytest
from fastapi.testclient import TestClient

os.environ["TESTING"] = "1"

from src.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_token(client):
    """Register a test user and return a valid JWT token."""
    import uuid
    email = f"test-{uuid.uuid4().hex[:8]}@governlayer.test"
    response = client.post("/auth/register", json={
        "email": email,
        "password": "TestPassword123",
        "company": "TestCorp",
    })
    if response.status_code == 400:
        # Already exists, login instead
        response = client.post("/auth/login", json={
            "email": email,
            "password": "TestPassword123",
        })
    return response.json()["token"]


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
