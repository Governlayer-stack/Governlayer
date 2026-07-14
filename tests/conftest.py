import os
import pytest
from fastapi.testclient import TestClient

os.environ["TESTING"] = "1"

from src.main import app
from src.models.database import Base, engine, create_tables


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all tables before any tests run."""
    create_tables()
    # Also import tenant models to register them
    try:
        import src.models.tenant  # noqa: F401
    except Exception:
        pass
    # Import the newer models so their tables are on Base.metadata
    try:
        import src.models.privacy  # noqa: F401
    except Exception:
        pass
    try:
        import src.models.webhooks  # noqa: F401
    except Exception:
        pass
    Base.metadata.create_all(bind=engine)

    # New columns added to api_keys after initial CREATE need to be applied
    # against the persisted schema for tests. create_all is a no-op for
    # existing tables, so we add missing columns idempotently here.
    if engine.dialect.name == "postgresql":
        with engine.connect() as conn:
            from sqlalchemy import text as sa_text
            for stmt in [
                "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS agent_id INTEGER",
                "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS principal_type VARCHAR(16) DEFAULT 'user' NOT NULL",
                "ALTER TABLE api_keys ALTER COLUMN org_id DROP NOT NULL",
            ]:
                try:
                    with conn.begin():
                        conn.execute(sa_text(stmt))
                except Exception:
                    pass

    # Ensure new enum values that were added after the initial CREATE TYPE
    # are present. Alembic handles this for production; for pytest (which
    # calls create_all directly), we run the ADD VALUE here idempotently.
    if engine.dialect.name == "postgresql":
        with engine.connect() as conn:
            from sqlalchemy import text as sa_text
            for enum_val in ("KILLED",):
                try:
                    with conn.begin():
                        conn.execute(sa_text(
                            f"ALTER TYPE agentstatus ADD VALUE IF NOT EXISTS '{enum_val}'"
                        ))
                except Exception:
                    pass
    yield


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_token(client):
    """Register a test user, verify their email, and return a valid JWT token."""
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
    token = response.json()["token"]

    # Auto-verify the test user's email so endpoints don't reject them
    from src.models.database import SessionLocal, User
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user and not user.email_verified:
            user.email_verified = True
            db.commit()
    finally:
        db.close()

    return token


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
