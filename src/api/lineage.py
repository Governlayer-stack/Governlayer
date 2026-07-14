"""Model Registry, Lineage & EU AI Act Annex IV Technical Documentation.

Persists model cards (versioned), tracks training-data sources, evals, intended
use, known limitations, and links each registered model to the decisions it
made (via the audit ledger reference). Produces a regulator-shaped technical
documentation export aligned with EU AI Act Annex IV (the "high-risk AI system
technical documentation" requirement).

Endpoints:
  POST /lineage/models                       - Register a new model card
  GET  /lineage/models                       - List registered models
  GET  /lineage/models/{model_id}            - Fetch full model card
  POST /lineage/models/{model_id}/versions   - Register a new version
  POST /lineage/models/{model_id}/evals      - Attach an eval result
  POST /lineage/models/{model_id}/datasets   - Attach a training-data source
  POST /lineage/decisions                    - Link a decision_id to (model, version)
  GET  /lineage/decisions/{decision_id}      - Lineage path for a decision
  GET  /lineage/models/{model_id}/annex-iv   - Generate Annex IV documentation export
  GET  /lineage/stats
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/lineage", tags=["lineage"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class DatasetSource(BaseModel):
    name: str
    description: str = ""
    source_url: Optional[str] = None
    license: Optional[str] = None
    record_count: Optional[int] = None
    collection_method: Optional[str] = None
    pii_handling: Optional[str] = None
    bias_assessment: Optional[str] = None
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvalResult(BaseModel):
    eval_name: str
    metric: str
    score: float
    dataset: Optional[str] = None
    notes: str = ""
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelVersion(BaseModel):
    version: str
    base_model: Optional[str] = None
    weights_hash: Optional[str] = Field(None, description="SHA-256 of weights file, if known")
    training_compute: Optional[str] = None
    released_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    change_notes: str = ""


class ModelCardCreate(BaseModel):
    name: str
    provider: str = Field(..., description="anthropic | openai | groq | ollama | custom | ...")
    family: str = Field(..., description="e.g. claude-3.5 / gpt-4o / llama3")
    intended_use: str
    out_of_scope_use: str = ""
    known_limitations: str = ""
    risk_classification: str = Field(
        default="limited",
        description="minimal | limited | high | unacceptable (EU AI Act categories)",
    )
    primary_users: str = ""
    owner: str = ""


class ModelCard(ModelCardCreate):
    model_id: str
    versions: list[ModelVersion] = []
    datasets: list[DatasetSource] = []
    evals: list[EvalResult] = []
    created_at: datetime
    updated_at: datetime


class DecisionLink(BaseModel):
    decision_id: str
    model_id: str
    version: str
    policy_version: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

_models: dict[str, ModelCard] = {}
_decision_links: dict[str, DecisionLink] = {}
_model_to_decisions: dict[str, list[str]] = defaultdict(list)


# ---------------------------------------------------------------------------
# Endpoints — registry
# ---------------------------------------------------------------------------

@router.post("/models", response_model=ModelCard, status_code=201)
def register_model(card: ModelCardCreate) -> ModelCard:
    model_id = f"mdl_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    full = ModelCard(
        model_id=model_id,
        created_at=now,
        updated_at=now,
        **card.model_dump(),
    )
    _models[model_id] = full
    return full


@router.get("/models")
def list_models() -> dict:
    return {"models": list(_models.values()), "count": len(_models)}


@router.get("/models/{model_id}", response_model=ModelCard)
def get_model(model_id: str) -> ModelCard:
    if model_id not in _models:
        raise HTTPException(status_code=404, detail="Model not found")
    return _models[model_id]


@router.post("/models/{model_id}/versions", response_model=ModelCard)
def add_version(model_id: str, version: ModelVersion) -> ModelCard:
    if model_id not in _models:
        raise HTTPException(status_code=404, detail="Model not found")
    card = _models[model_id]
    if any(v.version == version.version for v in card.versions):
        raise HTTPException(status_code=409, detail=f"Version {version.version} already exists")
    card.versions.append(version)
    card.updated_at = datetime.now(timezone.utc)
    return card


@router.post("/models/{model_id}/evals", response_model=ModelCard)
def add_eval(model_id: str, eval_result: EvalResult) -> ModelCard:
    if model_id not in _models:
        raise HTTPException(status_code=404, detail="Model not found")
    card = _models[model_id]
    card.evals.append(eval_result)
    card.updated_at = datetime.now(timezone.utc)
    return card


@router.post("/models/{model_id}/datasets", response_model=ModelCard)
def add_dataset(model_id: str, dataset: DatasetSource) -> ModelCard:
    if model_id not in _models:
        raise HTTPException(status_code=404, detail="Model not found")
    card = _models[model_id]
    card.datasets.append(dataset)
    card.updated_at = datetime.now(timezone.utc)
    return card


# ---------------------------------------------------------------------------
# Bulk ingest — populate the lineage graph from an external catalog export
# ---------------------------------------------------------------------------

class CatalogModelEntry(BaseModel):
    """One row from a catalog manifest — becomes a ModelCard + attached datasets."""
    name: str
    provider: str = "custom"
    family: str = "unknown"
    intended_use: str = "imported from catalog"
    known_limitations: str = ""
    risk_classification: str = "limited"
    owner: str = ""
    datasets: list[DatasetSource] = Field(default_factory=list)


class CatalogIngest(BaseModel):
    source_system: str = Field(..., description="e.g. 'dbt', 'unity_catalog', 'atlan', 'custom_export'")
    source_uri: Optional[str] = Field(default=None, description="Where the catalog came from")
    models: list[CatalogModelEntry] = Field(default_factory=list,
                                            description="Model entries to create or update")


@router.post("/catalog/ingest")
def ingest_catalog(manifest: CatalogIngest) -> dict:
    """Bulk-populate the lineage graph from a data-catalog export.

    Idempotent-ish on model.name: an existing model with the same name gets
    dataset entries appended (deduped by dataset name) rather than
    replaced. Provides a single-call bridge from external data catalogs
    (dbt manifest.json, Unity Catalog, Atlan export) into the /lineage
    graph, so Layer 2 (Data Foundation) has an actual ingest pipeline
    rather than being empty by default.

    Returns a summary suitable for a CI job or a UI toast:

        {
          "source_system": "dbt",
          "models_created":   N,
          "models_updated":   M,
          "datasets_added":   K,
          "duplicates_skipped": D
        }
    """
    now = datetime.now(timezone.utc)
    created = updated = datasets_added = duplicates = 0

    for entry in manifest.models:
        # Look up existing by name
        existing = next((c for c in _models.values() if c.name == entry.name), None)
        if existing is None:
            model_id = f"mdl_{uuid.uuid4().hex[:12]}"
            card = ModelCard(
                model_id=model_id,
                name=entry.name,
                provider=entry.provider,
                family=entry.family,
                intended_use=entry.intended_use,
                known_limitations=entry.known_limitations,
                risk_classification=entry.risk_classification,
                owner=entry.owner,
                created_at=now,
                updated_at=now,
                datasets=[],
                versions=[],
                evals=[],
            )
            _models[model_id] = card
            created += 1
        else:
            card = existing
            updated += 1

        # Merge datasets by name
        existing_names = {d.name for d in card.datasets}
        for ds in entry.datasets:
            if ds.name in existing_names:
                duplicates += 1
                continue
            card.datasets.append(ds)
            existing_names.add(ds.name)
            datasets_added += 1

        card.updated_at = now

    return {
        "source_system": manifest.source_system,
        "source_uri": manifest.source_uri,
        "ingested_at": now.isoformat(),
        "models_in_manifest": len(manifest.models),
        "models_created": created,
        "models_updated": updated,
        "datasets_added": datasets_added,
        "duplicates_skipped": duplicates,
    }


# ---------------------------------------------------------------------------
# Endpoints — decision linkage
# ---------------------------------------------------------------------------

@router.post("/decisions", response_model=DecisionLink, status_code=201)
def link_decision(link: DecisionLink) -> DecisionLink:
    if link.model_id not in _models:
        raise HTTPException(status_code=404, detail="Model not found")
    card = _models[link.model_id]
    if not any(v.version == link.version for v in card.versions):
        raise HTTPException(status_code=400, detail=f"Version {link.version} not registered for model")
    _decision_links[link.decision_id] = link
    _model_to_decisions[link.model_id].append(link.decision_id)
    return link


@router.get("/decisions/{decision_id}")
def get_decision_lineage(decision_id: str) -> dict:
    if decision_id not in _decision_links:
        raise HTTPException(status_code=404, detail="Decision lineage not found")
    link = _decision_links[decision_id]
    card = _models[link.model_id]
    version = next((v for v in card.versions if v.version == link.version), None)
    return {
        "decision_id": decision_id,
        "model": {
            "model_id": card.model_id,
            "name": card.name,
            "provider": card.provider,
            "family": card.family,
            "risk_classification": card.risk_classification,
        },
        "version": version.model_dump() if version else {"version": link.version, "note": "version metadata not found"},
        "policy_version": link.policy_version,
        "timestamp": link.timestamp,
        "datasets_used": [d.name for d in card.datasets],
        "evals_at_release": [e.eval_name + ":" + e.metric + "=" + str(e.score) for e in card.evals],
    }


# ---------------------------------------------------------------------------
# Annex IV technical-documentation export
# ---------------------------------------------------------------------------

@router.get("/models/{model_id}/annex-iv")
def annex_iv(model_id: str) -> dict:
    """Generate EU AI Act Annex IV technical documentation.

    Sections follow the Annex IV outline (general description, intended purpose,
    system architecture, data, monitoring, risk, performance). Section IDs are
    indicative of the Annex IV numbering; legal counsel should verify the final
    artifact before submission.
    """
    if model_id not in _models:
        raise HTTPException(status_code=404, detail="Model not found")
    card = _models[model_id]
    latest = card.versions[-1] if card.versions else None
    decision_count = len(_model_to_decisions.get(model_id, []))

    return {
        "annex_iv_export": {
            "generated_at": datetime.now(timezone.utc),
            "model_id": model_id,
            "sections": {
                "1_general_description": {
                    "system_name": card.name,
                    "provider": card.provider,
                    "model_family": card.family,
                    "intended_purpose": card.intended_use,
                    "out_of_scope_use": card.out_of_scope_use,
                    "primary_users": card.primary_users,
                    "system_owner": card.owner,
                    "risk_classification": card.risk_classification,
                },
                "2_detailed_description": {
                    "versions": [v.model_dump() for v in card.versions],
                    "current_version": latest.model_dump() if latest else None,
                    "computational_resources": latest.training_compute if latest else None,
                    "weights_integrity_hash": latest.weights_hash if latest else None,
                },
                "3_data_governance": {
                    "training_data_sources": [d.model_dump() for d in card.datasets],
                    "data_collection_methodology": [d.collection_method for d in card.datasets if d.collection_method],
                    "pii_handling": [d.pii_handling for d in card.datasets if d.pii_handling],
                    "bias_assessment": [d.bias_assessment for d in card.datasets if d.bias_assessment],
                },
                "4_performance_metrics": {
                    "evaluations": [e.model_dump() for e in card.evals],
                    "evaluation_count": len(card.evals),
                },
                "5_risk_management": {
                    "known_limitations": card.known_limitations,
                    "out_of_scope_use": card.out_of_scope_use,
                    "risk_classification": card.risk_classification,
                },
                "6_post_market_monitoring": {
                    "decisions_logged": decision_count,
                    "lineage_tracking_enabled": True,
                    "audit_ledger_reference": "see /ledger for hash-chained decision records",
                },
                "7_change_log": [
                    {"version": v.version, "released_at": v.released_at, "notes": v.change_notes}
                    for v in card.versions
                ],
            },
            "annex_iv_completeness": _annex_iv_completeness(card),
        }
    }


def _annex_iv_completeness(card: ModelCard) -> dict:
    checks = {
        "has_intended_use": bool(card.intended_use.strip()),
        "has_out_of_scope": bool(card.out_of_scope_use.strip()),
        "has_known_limitations": bool(card.known_limitations.strip()),
        "has_versions": len(card.versions) > 0,
        "has_datasets": len(card.datasets) > 0,
        "has_evals": len(card.evals) > 0,
        "has_owner": bool(card.owner.strip()),
        "has_risk_classification": card.risk_classification in {"minimal", "limited", "high", "unacceptable"},
    }
    score = sum(1 for v in checks.values() if v) / len(checks)
    return {"checks": checks, "completeness_score": round(score, 2)}


@router.get("/stats")
def stats() -> dict:
    return {
        "models_registered": len(_models),
        "decisions_linked": len(_decision_links),
        "by_provider": {
            provider: sum(1 for c in _models.values() if c.provider == provider)
            for provider in {c.provider for c in _models.values()}
        },
    }
