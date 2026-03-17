import hashlib
import json
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from src.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=300,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    company = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reset_token = Column(String(64), nullable=True)
    reset_token_expires_at = Column(DateTime, nullable=True)


class AuditRecord(Base):
    __tablename__ = "audit_records"
    id = Column(Integer, primary_key=True, index=True)
    decision_id = Column(String(64), unique=True, index=True, nullable=False)
    system_name = Column(String(255), nullable=False)
    industry = Column(String(255))
    audited_by = Column(String(255), nullable=False)
    frameworks_audited = Column(Text)
    results = Column(Text)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    governance_action = Column(String(50), default="PENDING", nullable=False)
    policy_version = Column(String(20), default="1.0.0", nullable=False)
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class RiskScoreRecord(Base):
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True, index=True)
    system_name = Column(String(255), nullable=False)
    overall_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    privacy_score = Column(Float, nullable=False)
    autonomy_score = Column(Float, nullable=False)
    infrastructure_score = Column(Float, nullable=False)
    oversight_score = Column(Float, nullable=False)
    transparency_score = Column(Float, nullable=False)
    fairness_score = Column(Float, nullable=False)
    scored_by = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class MutationLog(Base):
    """Tracks who changed what across all entities."""
    __tablename__ = "mutation_logs"
    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(255), nullable=False)  # email or api key identity
    action = Column(String(50), nullable=False)   # create, update, delete
    resource_type = Column(String(100), nullable=False)  # model, incident, agent, etc.
    resource_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)  # JSON summary of what changed
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


def log_mutation(db, actor: str, action: str, resource_type: str,
                 resource_id=None, details: str | None = None):
    """Record a mutation in the audit trail."""
    entry = MutationLog(
        actor=actor, action=action, resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        details=details,
    )
    db.add(entry)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def compute_hash(record_data: dict) -> str:
    canonical = json.dumps(record_data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def get_last_hash(db) -> str:
    """Get the last hash in the audit chain with row locking to prevent TOCTOU races."""
    last = db.query(AuditRecord).order_by(AuditRecord.id.desc()).with_for_update().first()
    if last:
        return last.current_hash
    return hashlib.sha256(b"GOVERNLAYER_GENESIS").hexdigest()


def create_tables():
    Base.metadata.create_all(bind=engine)
