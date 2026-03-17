"""API Usage Analytics — usage trends, latency stats, top endpoints, error rates."""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from src.models.database import get_db, AuditRecord
from src.models.tenant import UsageRecord, Organization, ApiKey
from src.security.api_key_auth import AuthContext, require_scope, verify_api_key_or_jwt

router = APIRouter(prefix="/v1/analytics/usage", tags=["Usage Analytics"])


@router.get("/summary")
def usage_summary(days: int = Query(default=30, ge=1, le=365),
                  db: Session = Depends(get_db)):
    """High-level usage summary for the organization."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    total = db.query(func.count(UsageRecord.id)).filter(
        UsageRecord.created_at >= cutoff
    ).scalar() or 0

    avg_latency = db.query(func.avg(UsageRecord.latency_ms)).filter(
        UsageRecord.created_at >= cutoff,
        UsageRecord.latency_ms.isnot(None),
    ).scalar()

    error_count = db.query(func.count(UsageRecord.id)).filter(
        UsageRecord.created_at >= cutoff,
        UsageRecord.status_code >= 400,
    ).scalar() or 0

    success_count = db.query(func.count(UsageRecord.id)).filter(
        UsageRecord.created_at >= cutoff,
        UsageRecord.status_code < 400,
    ).scalar() or 0

    # Unique API keys active
    active_keys = db.query(func.count(func.distinct(UsageRecord.api_key_id))).filter(
        UsageRecord.created_at >= cutoff,
        UsageRecord.api_key_id.isnot(None),
    ).scalar() or 0

    return {
        "period_days": days,
        "total_requests": total,
        "success_count": success_count,
        "error_count": error_count,
        "error_rate": round(error_count / total * 100, 2) if total > 0 else 0,
        "average_latency_ms": round(avg_latency, 2) if avg_latency else 0,
        "active_api_keys": active_keys,
        "requests_per_day": round(total / days, 1) if days > 0 else 0,
    }


@router.get("/trends")
def usage_trends(days: int = Query(default=30, ge=1, le=365),
                 granularity: str = Query(default="day", pattern=r"^(hour|day|week)$"),
                 db: Session = Depends(get_db)):
    """Request volume over time — powers line charts."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    # SQLAlchemy date truncation
    if granularity == "hour":
        trunc = func.date_trunc("hour", UsageRecord.created_at)
    elif granularity == "week":
        trunc = func.date_trunc("week", UsageRecord.created_at)
    else:
        trunc = func.date_trunc("day", UsageRecord.created_at)

    rows = db.query(
        trunc.label("period"),
        func.count(UsageRecord.id).label("requests"),
        func.avg(UsageRecord.latency_ms).label("avg_latency"),
        func.count(case((UsageRecord.status_code >= 400, 1))).label("errors"),
    ).filter(
        UsageRecord.created_at >= cutoff,
    ).group_by("period").order_by("period").all()

    return {
        "granularity": granularity,
        "period_days": days,
        "data_points": [
            {
                "period": r.period.isoformat() if r.period else None,
                "requests": r.requests,
                "avg_latency_ms": round(r.avg_latency, 2) if r.avg_latency else 0,
                "errors": r.errors,
            }
            for r in rows
        ],
    }


@router.get("/top-endpoints")
def top_endpoints(days: int = Query(default=30, ge=1, le=365),
                  limit: int = Query(default=10, ge=1, le=50),
                  db: Session = Depends(get_db)):
    """Most-used API endpoints — powers bar charts."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    rows = db.query(
        UsageRecord.endpoint,
        UsageRecord.method,
        func.count(UsageRecord.id).label("count"),
        func.avg(UsageRecord.latency_ms).label("avg_latency"),
        func.count(case((UsageRecord.status_code >= 400, 1))).label("errors"),
    ).filter(
        UsageRecord.created_at >= cutoff,
    ).group_by(UsageRecord.endpoint, UsageRecord.method
    ).order_by(func.count(UsageRecord.id).desc()
    ).limit(limit).all()

    return {
        "period_days": days,
        "endpoints": [
            {
                "endpoint": r.endpoint,
                "method": r.method,
                "count": r.count,
                "avg_latency_ms": round(r.avg_latency, 2) if r.avg_latency else 0,
                "error_count": r.errors,
            }
            for r in rows
        ],
    }


@router.get("/latency")
def latency_stats(days: int = Query(default=30, ge=1, le=365),
                  db: Session = Depends(get_db)):
    """Latency percentiles and distribution."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    stats = db.query(
        func.min(UsageRecord.latency_ms).label("min"),
        func.max(UsageRecord.latency_ms).label("max"),
        func.avg(UsageRecord.latency_ms).label("avg"),
        func.count(UsageRecord.id).label("total"),
    ).filter(
        UsageRecord.created_at >= cutoff,
        UsageRecord.latency_ms.isnot(None),
    ).first()

    # Percentiles via percentile_cont (PostgreSQL)
    p50 = p95 = p99 = None
    try:
        from sqlalchemy import text
        row = db.execute(text("""
            SELECT
                percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) as p50,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95,
                percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99
            FROM usage_records
            WHERE created_at >= :cutoff AND latency_ms IS NOT NULL
        """), {"cutoff": cutoff}).first()
        if row:
            p50 = round(row.p50, 2) if row.p50 else None
            p95 = round(row.p95, 2) if row.p95 else None
            p99 = round(row.p99, 2) if row.p99 else None
    except Exception:
        pass

    return {
        "period_days": days,
        "total_samples": stats.total if stats else 0,
        "min_ms": round(stats.min, 2) if stats and stats.min else 0,
        "max_ms": round(stats.max, 2) if stats and stats.max else 0,
        "avg_ms": round(stats.avg, 2) if stats and stats.avg else 0,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
    }


@router.get("/errors")
def error_breakdown(days: int = Query(default=30, ge=1, le=365),
                    db: Session = Depends(get_db)):
    """Error rate breakdown by status code."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    rows = db.query(
        UsageRecord.status_code,
        func.count(UsageRecord.id).label("count"),
    ).filter(
        UsageRecord.created_at >= cutoff,
        UsageRecord.status_code >= 400,
    ).group_by(UsageRecord.status_code
    ).order_by(func.count(UsageRecord.id).desc()).all()

    total_errors = sum(r.count for r in rows)
    total_requests = db.query(func.count(UsageRecord.id)).filter(
        UsageRecord.created_at >= cutoff,
    ).scalar() or 0

    return {
        "period_days": days,
        "total_errors": total_errors,
        "total_requests": total_requests,
        "error_rate": round(total_errors / total_requests * 100, 2) if total_requests > 0 else 0,
        "by_status_code": [
            {"status_code": r.status_code, "count": r.count}
            for r in rows
        ],
    }


@router.get("/governance")
def governance_analytics(days: int = Query(default=30, ge=1, le=365),
                         db: Session = Depends(get_db)):
    """Governance decision analytics — approve/block/escalate breakdown."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    rows = db.query(
        AuditRecord.governance_action,
        func.count(AuditRecord.id).label("count"),
        func.avg(AuditRecord.risk_score).label("avg_risk"),
    ).filter(
        AuditRecord.created_at >= cutoff,
    ).group_by(AuditRecord.governance_action).all()

    total = sum(r.count for r in rows)

    return {
        "period_days": days,
        "total_decisions": total,
        "by_action": [
            {
                "action": r.governance_action,
                "count": r.count,
                "percentage": round(r.count / total * 100, 1) if total > 0 else 0,
                "avg_risk_score": round(r.avg_risk, 1) if r.avg_risk else 0,
            }
            for r in rows
        ],
    }
