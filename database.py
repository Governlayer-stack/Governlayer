from sqlalchemy import create_engine, Column, String, Float, DateTime, Text, Boolean, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import hashlib
import json
import os

DATABASE_URL = "postgresql://localhost/governlayer"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AuditRecord(Base):
    __tablename__ = "audit_records"
    id = Column(Integer, primary_key=True, index=True)
    decision_id = Column(String, unique=True, index=True)
    system_name = Column(String)
    industry = Column(String)
    audited_by = Column(String)
    frameworks_audited = Column(Text)
    results = Column(Text)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True)
    governance_action = Column(String, default="PENDING")
    policy_version = Column(String, default="1.0.0")
    previous_hash = Column(String)
    current_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class RiskScoreRecord(Base):
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True, index=True)
    system_name = Column(String)
    overall_score = Column(Float)
    risk_level = Column(String)
    privacy_score = Column(Float)
    autonomy_score = Column(Float)
    infrastructure_score = Column(Float)
    oversight_score = Column(Float)
    transparency_score = Column(Float)
    fairness_score = Column(Float)
    scored_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    company = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

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
    last = db.query(AuditRecord).order_by(AuditRecord.id.desc()).first()
    if last:
        return last.current_hash
    return hashlib.sha256(b"GOVERNLAYER_GENESIS").hexdigest()

def create_tables():
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")

if __name__ == "__main__":
    create_tables()
