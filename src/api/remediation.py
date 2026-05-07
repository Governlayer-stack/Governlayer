"""Remediation Workflow API — assign, track, and close compliance gaps."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.security.auth import verify_token

router = APIRouter(prefix="/v1/remediation", tags=["Remediation"])

# In-memory task store (production: DB table)
_tasks: dict[str, dict] = {}


class TaskCreate(BaseModel):
    control_id: str
    title: str
    description: str = ""
    assignee: str = ""
    priority: str = Field(default="medium", description="low | medium | high | critical")
    due_date: Optional[str] = None
    jira_key: Optional[str] = None


class TaskUpdate(BaseModel):
    status: Optional[str] = None  # open | in_progress | blocked | done
    assignee: Optional[str] = None
    priority: Optional[str] = None
    due_date: Optional[str] = None
    notes: Optional[str] = None
    jira_key: Optional[str] = None


@router.get("")
def list_tasks(
    status: Optional[str] = Query(None),
    assignee: Optional[str] = Query(None),
    control_id: Optional[str] = Query(None),
    email: str = Depends(verify_token),
):
    """List all remediation tasks, optionally filtered."""
    tasks = list(_tasks.values())
    if status:
        tasks = [t for t in tasks if t["status"] == status]
    if assignee:
        tasks = [t for t in tasks if t["assignee"] == assignee]
    if control_id:
        tasks = [t for t in tasks if t["control_id"] == control_id]

    overdue = sum(1 for t in tasks if t.get("due_date") and t["status"] != "done"
                  and t["due_date"] < datetime.now(timezone.utc).isoformat())

    return {
        "total": len(tasks),
        "overdue": overdue,
        "by_status": {
            "open": sum(1 for t in tasks if t["status"] == "open"),
            "in_progress": sum(1 for t in tasks if t["status"] == "in_progress"),
            "blocked": sum(1 for t in tasks if t["status"] == "blocked"),
            "done": sum(1 for t in tasks if t["status"] == "done"),
        },
        "tasks": sorted(tasks, key=lambda t: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(t["priority"], 2),
            t.get("due_date") or "9999",
        )),
    }


@router.post("")
def create_task(data: TaskCreate, email: str = Depends(verify_token)):
    """Create a remediation task for a failing control."""
    if data.priority not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="Priority must be low|medium|high|critical")

    task_id = f"REM-{str(uuid.uuid4())[:8].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    task = {
        "id": task_id,
        "control_id": data.control_id,
        "title": data.title,
        "description": data.description,
        "assignee": data.assignee or email,
        "priority": data.priority,
        "status": "open",
        "due_date": data.due_date,
        "jira_key": data.jira_key,
        "created_by": email,
        "created_at": now,
        "updated_at": now,
        "notes": [],
    }
    _tasks[task_id] = task
    return task


@router.get("/{task_id}")
def get_task(task_id: str, email: str = Depends(verify_token)):
    """Get a single remediation task by ID."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.patch("/{task_id}")
def update_task(task_id: str, data: TaskUpdate, email: str = Depends(verify_token)):
    """Update a remediation task (status, assignee, notes, etc.)."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    valid_statuses = ("open", "in_progress", "blocked", "done")
    if data.status and data.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of {valid_statuses}")

    if data.status:
        task["status"] = data.status
    if data.assignee is not None:
        task["assignee"] = data.assignee
    if data.priority is not None:
        task["priority"] = data.priority
    if data.due_date is not None:
        task["due_date"] = data.due_date
    if data.jira_key is not None:
        task["jira_key"] = data.jira_key
    if data.notes:
        task["notes"].append({
            "author": email,
            "text": data.notes,
            "at": datetime.now(timezone.utc).isoformat(),
        })
    task["updated_at"] = datetime.now(timezone.utc).isoformat()
    return task


@router.delete("/{task_id}")
def delete_task(task_id: str, email: str = Depends(verify_token)):
    """Delete a remediation task."""
    if task_id not in _tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    del _tasks[task_id]
    return {"deleted": task_id}


@router.get("/summary/stats")
def remediation_stats(email: str = Depends(verify_token)):
    """Remediation dashboard stats — completion rate, SLA compliance, etc."""
    tasks = list(_tasks.values())
    total = len(tasks)
    done = sum(1 for t in tasks if t["status"] == "done")
    now = datetime.now(timezone.utc).isoformat()
    overdue = sum(1 for t in tasks if t.get("due_date") and t["status"] != "done" and t["due_date"] < now)

    return {
        "total_tasks": total,
        "completed": done,
        "completion_rate": round(done / total * 100, 1) if total else 0,
        "overdue": overdue,
        "sla_compliance": round((total - overdue) / total * 100, 1) if total else 100,
        "by_priority": {
            p: sum(1 for t in tasks if t["priority"] == p)
            for p in ("critical", "high", "medium", "low")
        },
        "avg_age_days": round(
            sum(
                (datetime.now(timezone.utc) - datetime.fromisoformat(t["created_at"].replace("Z", "+00:00"))).days
                for t in tasks if t["status"] != "done"
            ) / max(1, total - done),
            1,
        ) if tasks else 0,
    }
