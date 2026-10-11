"""Atomic status files shared by the capture process and local UI."""
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATUS_FILE = ROOT / "data" / "capture_status.json"
STOP_FILE = ROOT / "data" / "capture.stop"


def write_status(**values):
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    values.update(updated_at=time.time(), pid=os.getpid())
    temporary = STATUS_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(values), encoding="utf-8")
    temporary.replace(STATUS_FILE)


def read_status():
    try:
        values = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        if time.time() - values.get("updated_at", 0) > 30 and values.get("state") in {"running", "starting"}:
            values["state"] = "unavailable"
            values["message"] = "Capture heartbeat is stale. Check the capture terminal."
        return values
    except (OSError, ValueError):
        return {"state": "stopped", "interface": None, "ml_loaded": None}
