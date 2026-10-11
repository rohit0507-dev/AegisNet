"""Local-only capture lifecycle; arguments never pass through a shell."""
import atexit
import os
import subprocess
import sys
import threading

from app.capture.runtime import ROOT, STOP_FILE, read_status, write_status

_process = None
_lock = threading.Lock()


def interfaces():
    from scapy.all import conf
    return [{"id": str(i.index), "name": i.name, "description": i.description or i.name,
             "ip": i.ip or "No IPv4 address"} for i in conf.ifaces.values()]


def status():
    result = read_status()
    result["managed"] = _process is not None and _process.poll() is None
    if _process is not None and _process.poll() is not None and result.get("state") in {"running", "starting"}:
        result.update(state="error", message="Capture exited. Check data/capture.log and Npcap permissions.")
    return result


def start(interface):
    global _process
    with _lock:
        if status().get("state") in {"running", "starting"}:
            raise ValueError("Capture is already running. Stop it before changing adapters.")
        valid = {item["id"]: item for item in interfaces()}
        if str(interface) not in valid:
            raise ValueError("Choose an available network adapter.")
        STOP_FILE.unlink(missing_ok=True)
        write_status(state="starting", interface=valid[str(interface)]["name"], ml_loaded=None)
        with (ROOT / "data" / "capture.log").open("a", encoding="utf-8") as log:
            _process = subprocess.Popen(
                [sys.executable, "-u", str(ROOT / "main.py"), "--interface", str(interface)],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1", "AEGISNET_MANAGED_CAPTURE": "1"},
            )
        return status()


def stop():
    with _lock:
        if _process is None or _process.poll() is not None:
            raise ValueError("This capture was not started by this dashboard. Stop it in its terminal.")
        STOP_FILE.touch()
        return {**status(), "message": "Stopping capture and saving the final flow window…"}


@atexit.register
def shutdown():
    if _process is not None and _process.poll() is None:
        STOP_FILE.touch()
        try:
            _process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            _process.terminate()
