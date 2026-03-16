#!/usr/bin/env python3
"""GovernLayer Autonomous Daemon — runs the full governance pipeline on schedule.

Usage:
    python3 scripts/governlayer_daemon.py                # Run once
    python3 scripts/governlayer_daemon.py --loop 300     # Run every 5 minutes
    python3 scripts/governlayer_daemon.py --loop 3600    # Run every hour

The daemon:
1. Registers a bot account (or reuses existing)
2. Runs full-pipeline on all configured systems
3. Logs results to ~/.governlayer/daemon.log
4. Sends alerts on BLOCK/ESCALATE actions
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

API_BASE = os.environ.get("GOVERNLAYER_API", "http://localhost:8000")
BOT_NAME = os.environ.get("GOVERNLAYER_BOT", "daemon-agent")
BOT_PASSWORD = os.environ.get("GOVERNLAYER_BOT_PASSWORD", "governlayer-daemon-2026")
LOG_DIR = Path.home() / ".governlayer"
LOG_FILE = LOG_DIR / "daemon.log"

# Systems to monitor — add your AI systems here
MONITORED_SYSTEMS = [
    {
        "system_name": "GovernLayer API",
        "reasoning_trace": (
            "Processing governance request. Analyzing compliance against NIST AI RMF, "
            "EU AI Act, and ISO 42001 frameworks. Evaluating drift coefficients and "
            "risk dimensions. Generating hash-chained audit record."
        ),
        "use_case": "governance",
        "industry": "technology",
        "handles_personal_data": True,
        "makes_autonomous_decisions": True,
        "used_in_critical_infrastructure": False,
        "has_human_oversight": True,
        "is_explainable": True,
        "has_bias_testing": False,
        "system_description": "AI governance control plane with drift detection, risk scoring, and compliance auditing.",
        "frameworks": "NIST_AI_RMF,EU_AI_ACT,ISO_42001",
        "run_audit": True,
        "run_threats": False,
    },
    {
        "system_name": "Achonye Multi-LLM Orchestrator",
        "reasoning_trace": (
            "Routing task through Achonye hierarchy. Leader analyzes complexity, "
            "selects optimal model from 14-model registry. Applying token economics: "
            "local inference for simple tasks, cloud for complex. Running consensus "
            "validation on critical decisions."
        ),
        "use_case": "orchestration",
        "industry": "technology",
        "handles_personal_data": False,
        "makes_autonomous_decisions": True,
        "used_in_critical_infrastructure": False,
        "has_human_oversight": True,
        "is_explainable": True,
        "has_bias_testing": False,
        "system_description": "Multi-LLM orchestration with intelligent routing and consensus validation.",
        "frameworks": "NIST_AI_RMF,EU_AI_ACT,ISO_42001,OWASP_AI",
        "run_audit": False,
        "run_threats": False,
    },
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("governlayer-daemon")


def api_call(method: str, path: str, data: dict = None, token: str = None) -> dict:
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        log.error(f"API {method} {path} -> {e.code}: {error_body}")
        return {"error": e.code, "detail": error_body}
    except Exception as e:
        log.error(f"API {method} {path} -> {e}")
        return {"error": str(e)}


def get_bot_token() -> str:
    result = api_call("POST", "/automate/register-bot", {
        "bot_name": BOT_NAME,
        "password": BOT_PASSWORD,
    })
    if "token" in result:
        log.info(f"Bot authenticated: {result['email']}")
        return result["token"]
    log.error(f"Failed to register bot: {result}")
    sys.exit(1)


def run_pipeline(token: str) -> list:
    results = []
    for system in MONITORED_SYSTEMS:
        log.info(f"Running pipeline for: {system['system_name']}")
        result = api_call("POST", "/automate/full-pipeline", system, token=token)

        if "error" in result:
            log.error(f"  Pipeline failed: {result}")
            results.append({"system": system["system_name"], "status": "error", "detail": result})
            continue

        action = result.get("governance_action", "UNKNOWN")
        risk = result.get("risk_score", "?")
        drift = result.get("drift_coefficient", "?")
        elapsed = result.get("elapsed_seconds", "?")

        icon = {"APPROVE": "OK", "BLOCK": "BLOCKED", "ESCALATE_HUMAN": "ESCALATED"}.get(action, action)
        log.info(f"  [{icon}] risk={risk}/100 drift={drift} elapsed={elapsed}s")

        if action in ("BLOCK", "ESCALATE_HUMAN"):
            log.warning(f"  ACTION REQUIRED: {result.get('reason', '')}")

        results.append(result)

    return results


def check_health(token: str = None) -> dict:
    result = api_call("GET", "/automate/health")
    overall = result.get("overall", "unknown")
    services = result.get("services", {})
    log.info(f"System health: {overall}")
    for svc, status in services.items():
        log.info(f"  {svc}: {status.get('status', 'unknown')}")
    return result


def run_once(token: str):
    log.info("=" * 60)
    log.info(f"GovernLayer Daemon Run — {datetime.utcnow().isoformat()}")
    log.info("=" * 60)

    health = check_health()
    if health.get("overall") != "healthy":
        log.warning("System degraded — running pipeline anyway")

    results = run_pipeline(token)

    # Write results to log file
    LOG_DIR.mkdir(exist_ok=True)
    with open(LOG_FILE, "a") as f:
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "health": health.get("overall"),
            "results": [
                {
                    "system": r.get("system", r.get("system_name", "?")),
                    "action": r.get("governance_action", r.get("status", "?")),
                    "risk_score": r.get("risk_score"),
                    "drift_coefficient": r.get("drift_coefficient"),
                }
                for r in results
            ],
        }
        f.write(json.dumps(entry) + "\n")

    blocked = [r for r in results if r.get("governance_action") == "BLOCK"]
    escalated = [r for r in results if r.get("governance_action") == "ESCALATE_HUMAN"]

    log.info(f"Pipeline complete: {len(results)} systems, {len(blocked)} blocked, {len(escalated)} escalated")
    return results


def main():
    parser = argparse.ArgumentParser(description="GovernLayer Autonomous Daemon")
    parser.add_argument("--loop", type=int, default=0, help="Run every N seconds (0 = run once)")
    parser.add_argument("--health-only", action="store_true", help="Just check health")
    args = parser.parse_args()

    if args.health_only:
        check_health()
        return

    token = get_bot_token()

    if args.loop > 0:
        log.info(f"Starting continuous loop every {args.loop}s (Ctrl+C to stop)")
        while True:
            try:
                run_once(token)
                log.info(f"Next run in {args.loop}s...")
                time.sleep(args.loop)
            except KeyboardInterrupt:
                log.info("Daemon stopped by user")
                break
            except Exception as e:
                log.error(f"Run failed: {e}")
                time.sleep(30)
    else:
        run_once(token)


if __name__ == "__main__":
    main()
