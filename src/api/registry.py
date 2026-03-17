"""Model Registry API — CRUD + lifecycle management."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.models.database import SessionLocal
from src.models.registry import RegisteredModel, ModelCard, ModelLifecycle

router = APIRouter(prefix="/v1/models", tags=["Model Registry"])


class ModelCreate(BaseModel):
    name: str
    version: str
    provider: Optional[str] = None
    model_type: Optional[str] = None
    risk_tier: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    tags: list = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class ModelCardCreate(BaseModel):
    intended_use: Optional[str] = None
    limitations: Optional[str] = None
    training_data_summary: Optional[str] = None
    evaluation_metrics: dict = Field(default_factory=dict)
    ethical_considerations: Optional[str] = None
    fairness_analysis: dict = Field(default_factory=dict)


class LifecycleUpdate(BaseModel):
    lifecycle: str


@router.post("")
def register_model(data: ModelCreate):
    """Register a new AI model in the governance registry."""
    db = SessionLocal()
    try:
        model = RegisteredModel(
            name=data.name,
            version=data.version,
            provider=data.provider,
            model_type=data.model_type,
            risk_tier=data.risk_tier,
            description=data.description,
            owner=data.owner,
            tags=data.tags,
            metadata_=data.metadata,
            governance_status="pending",
        )
        db.add(model)
        db.commit()
        db.refresh(model)
        return {
            "id": model.id,
            "name": model.name,
            "version": model.version,
            "lifecycle": model.lifecycle.value if model.lifecycle else "development",
            "governance_status": model.governance_status,
            "created_at": model.created_at.isoformat() if model.created_at else None,
        }
    finally:
        db.close()


@router.get("")
def list_models(lifecycle: Optional[str] = None, governance_status: Optional[str] = None):
    """List all registered models with optional filters."""
    db = SessionLocal()
    try:
        query = db.query(RegisteredModel)
        if lifecycle:
            query = query.filter(RegisteredModel.lifecycle == lifecycle)
        if governance_status:
            query = query.filter(RegisteredModel.governance_status == governance_status)
        models = query.order_by(RegisteredModel.created_at.desc()).all()
        return {
            "total": len(models),
            "models": [
                {
                    "id": m.id,
                    "name": m.name,
                    "version": m.version,
                    "provider": m.provider,
                    "model_type": m.model_type,
                    "lifecycle": m.lifecycle.value if m.lifecycle else None,
                    "risk_tier": m.risk_tier,
                    "governance_status": m.governance_status,
                    "risk_score": m.risk_score,
                    "owner": m.owner,
                    "created_at": m.created_at.isoformat() if m.created_at else None,
                }
                for m in models
            ],
        }
    finally:
        db.close()


@router.get("/{model_id}")
def get_model(model_id: int):
    """Get detailed model information."""
    db = SessionLocal()
    try:
        model = db.query(RegisteredModel).filter(RegisteredModel.id == model_id).first()
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        return {
            "id": model.id,
            "name": model.name,
            "version": model.version,
            "provider": model.provider,
            "model_type": model.model_type,
            "lifecycle": model.lifecycle.value if model.lifecycle else None,
            "risk_tier": model.risk_tier,
            "description": model.description,
            "owner": model.owner,
            "tags": model.tags,
            "metadata": model.metadata_,
            "governance_status": model.governance_status,
            "risk_score": model.risk_score,
            "last_audit_at": model.last_audit_at.isoformat() if model.last_audit_at else None,
            "created_at": model.created_at.isoformat() if model.created_at else None,
            "updated_at": model.updated_at.isoformat() if model.updated_at else None,
        }
    finally:
        db.close()


@router.put("/{model_id}/lifecycle")
def update_lifecycle(model_id: int, data: LifecycleUpdate):
    """Promote or demote a model through lifecycle stages."""
    valid = [e.value for e in ModelLifecycle]
    if data.lifecycle not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid lifecycle. Must be one of: {valid}")

    db = SessionLocal()
    try:
        model = db.query(RegisteredModel).filter(RegisteredModel.id == model_id).first()
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        model.lifecycle = ModelLifecycle(data.lifecycle)
        model.updated_at = datetime.utcnow()
        db.commit()
        return {"id": model.id, "name": model.name, "lifecycle": data.lifecycle}
    finally:
        db.close()


@router.post("/{model_id}/card")
def create_model_card(model_id: int, data: ModelCardCreate):
    """Create or update a model card for transparency documentation."""
    db = SessionLocal()
    try:
        model = db.query(RegisteredModel).filter(RegisteredModel.id == model_id).first()
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        card = ModelCard(
            model_id=model_id,
            intended_use=data.intended_use,
            limitations=data.limitations,
            training_data_summary=data.training_data_summary,
            evaluation_metrics=data.evaluation_metrics,
            ethical_considerations=data.ethical_considerations,
            fairness_analysis=data.fairness_analysis,
        )
        db.add(card)
        db.commit()
        db.refresh(card)
        return {
            "id": card.id,
            "model_id": model_id,
            "intended_use": card.intended_use,
            "created_at": card.created_at.isoformat() if card.created_at else None,
        }
    finally:
        db.close()


@router.get("/{model_id}/card")
def get_model_card(model_id: int):
    """Get the latest model card."""
    db = SessionLocal()
    try:
        card = (
            db.query(ModelCard)
            .filter(ModelCard.model_id == model_id)
            .order_by(ModelCard.created_at.desc())
            .first()
        )
        if not card:
            raise HTTPException(status_code=404, detail="No model card found")
        return {
            "id": card.id,
            "model_id": card.model_id,
            "intended_use": card.intended_use,
            "limitations": card.limitations,
            "training_data_summary": card.training_data_summary,
            "evaluation_metrics": card.evaluation_metrics,
            "ethical_considerations": card.ethical_considerations,
            "fairness_analysis": card.fairness_analysis,
            "created_at": card.created_at.isoformat() if card.created_at else None,
        }
    finally:
        db.close()
