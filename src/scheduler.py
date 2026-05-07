"""Background Scheduler — executes evidence collection schedules and control checks.

Runs as a background thread inside the FastAPI process. On startup, it reads
EvidenceScheduleDB rows and fires evidence collection when next_run_at <= now.
Also runs all control checks every 15 minutes.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

logger = logging.getLogger("governlayer.scheduler")

_scheduler_thread: threading.Thread | None = None
_stop_event = threading.Event()

# Default intervals
TICK_INTERVAL = 60  # check every 60 seconds
CONTROL_CHECK_INTERVAL = 900  # run control checks every 15 min


def _run_evidence_collection(connector_name: str, connector_id: int, db: Session):
    """Execute evidence collection for a single connector."""
    from src.api.evidence import CONNECTORS, REAL_CONNECTOR_TYPES, _simulate_collection, _real_collection

    if connector_name not in CONNECTORS:
        logger.warning(f"Scheduler: unknown connector {connector_name}")
        return

    try:
        if connector_name in REAL_CONNECTOR_TYPES:
            from src.models.evidence import EvidenceConnectorDB
            connector_db = db.query(EvidenceConnectorDB).filter(
                EvidenceConnectorDB.id == connector_id
            ).first()
            if connector_db and connector_db.config_encrypted:
                import json
                config = json.loads(connector_db.config_encrypted)
                items = _real_collection(connector_name, config)
            else:
                items = _simulate_collection(connector_name)
        else:
            items = _simulate_collection(connector_name)

        logger.info(f"Scheduler: collected {len(items)} evidence items from {connector_name}")
    except Exception as e:
        logger.error(f"Scheduler: evidence collection failed for {connector_name}: {e}")


def _run_control_checks():
    """Run all control checks (same as POST /v1/controls/check)."""
    from src.api.controls import _controls, _seed_controls, _run_single_check

    _seed_controls()
    passing = 0
    failing = 0
    for control in _controls.values():
        result = _run_single_check(control)
        if result["status"] == "passing":
            passing += 1
        elif result["status"] == "failing":
            failing += 1

    logger.info(f"Scheduler: control check complete — {passing} passing, {failing} failing")


def _scheduler_loop():
    """Main scheduler loop — runs in background thread."""
    from src.models.database import SessionLocal
    from src.models.evidence import EvidenceScheduleDB, EvidenceConnectorDB

    logger.info("Background scheduler started")
    last_control_check = 0

    while not _stop_event.is_set():
        now = datetime.now(timezone.utc)

        # --- Evidence schedule execution ---
        try:
            db = SessionLocal()
            due_schedules = db.query(EvidenceScheduleDB).filter(
                EvidenceScheduleDB.enabled == True,
                EvidenceScheduleDB.next_run_at <= now,
            ).all()

            for schedule in due_schedules:
                connector = db.query(EvidenceConnectorDB).filter(
                    EvidenceConnectorDB.id == schedule.connector_id
                ).first()
                if connector:
                    _run_evidence_collection(connector.name, connector.id, db)
                    schedule.last_run_at = now
                    # Advance next_run based on cron expression
                    cron_deltas = {
                        "0 * * * *": timedelta(hours=1),
                        "0 0 * * *": timedelta(days=1),
                        "0 0 * * 0": timedelta(weeks=1),
                    }
                    delta = cron_deltas.get(schedule.cron_expression, timedelta(hours=1))
                    schedule.next_run_at = now + delta
                    db.commit()
                    logger.info(f"Scheduler: ran collection for {connector.name}, next at {schedule.next_run_at}")

            db.close()
        except Exception as e:
            logger.error(f"Scheduler: evidence schedule error: {e}")

        # --- Periodic control checks ---
        elapsed = time.time() - last_control_check
        if elapsed >= CONTROL_CHECK_INTERVAL:
            try:
                _run_control_checks()
                last_control_check = time.time()
            except Exception as e:
                logger.error(f"Scheduler: control check error: {e}")

        _stop_event.wait(TICK_INTERVAL)

    logger.info("Background scheduler stopped")


def start_scheduler():
    """Start the background scheduler thread."""
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _stop_event.clear()
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True, name="gl-scheduler")
    _scheduler_thread.start()


def stop_scheduler():
    """Stop the background scheduler."""
    _stop_event.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=5)
