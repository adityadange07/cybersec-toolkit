#!/usr/bin/env python3
"""
Web UI for the CyberSec Toolkit (FastAPI backend).

Serves a single-page frontend (static/index.html) and JSON/SSE API endpoints that
reuse the same dynamic module discovery as ui.py, running real BaseModule
subclasses. Modules run in a background thread; their log output is streamed to
the browser live via Server-Sent Events, and finished runs are kept in a history
store the UI can re-open.

Ethical-use note: this exposes live scanning/cracking modules over HTTP. Bind to
localhost only unless you have a controlled, authorized environment.
"""
import importlib
import inspect
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config.settings import config
from core.base_module import BaseModule
from core.logger import setup_logger

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="CyberSec Toolkit Web UI")

CATEGORY_LABELS = {
    "recon": "🔍 Reconnaissance",
    "vuln_scanner": "⚠️  Vulnerability Scanning",
    "network": "🌐 Network Tools",
    "mobile": "📱 Mobile Analysis",
    "malware_analysis": "🦠 Malware Analysis",
    "forensics": "🔍 Forensics",
    "password": "🔑 Password Attacks",
    "defensive": "🛡️ Defense & Monitoring",
    "reporting": "📄 Reporting",
    "exploitation": "💥 Exploitation",
    "reverse_engineering": "🧬 Reverse Engineering",
}

OPTION_HINTS = {
    "PortScanner": "scan_type=tcp|syn, port_range=1-1024, ports=80,443",
    "ServiceEnumerator": "ports=22,80,443, max_threads=10",
    "PasswordGenerator": "mode=password|passphrase|pin|apikey|uuid|check, "
                          "length=20, count=5, check_value=<pwd>",
}

# Modules that use `target` as a value/mode rather than a host.
NO_TARGET_MODULES = {"password": {"PasswordGenerator"}}

# In-memory run history (newest first). Also persisted to output/ as JSON.
RUN_HISTORY: List[Dict[str, Any]] = []
RUN_HISTORY_LOCK = threading.Lock()

# Per-run abort flags, keyed by run id.
ABORT_FLAGS: Dict[str, bool] = {}
ABORT_LOCK = threading.Lock()


def discover_modules() -> List[Dict[str, Any]]:
    """Return a list of module descriptors discovered under modules/."""
    modules_dir = BASE_DIR / "modules"
    found = []
    for category_dir in sorted(modules_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        for py_file in sorted(category_dir.glob("*.py")):
            if py_file.name.startswith("__"):
                continue
            module_name = f"modules.{category}.{py_file.stem}"
            try:
                mod = importlib.import_module(module_name)
            except Exception:
                continue
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseModule) and obj is not BaseModule:
                    if obj.__module__ == module_name:
                        found.append({
                            "id": f"{category}.{name}",
                            "name": name,
                            "category": category,
                            "module_file": py_file.stem,
                            "category_label": CATEGORY_LABELS.get(category, category),
                            "needs_target": not (
                                category in NO_TARGET_MODULES
                                and name in NO_TARGET_MODULES[category]
                            ),
                            "option_hint": OPTION_HINTS.get(name, ""),
                        })
    return found


MODULES = discover_modules()
MODULE_INDEX = {m["id"]: m for m in MODULES}


class RunRequest(BaseModel):
    module_id: str
    target: str = ""
    options: Dict[str, Any] = {}


def _load_class(module_id: str):
    meta = MODULE_INDEX.get(module_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Module not found")
    mod = importlib.import_module(f"modules.{meta['category']}.{meta['module_file']}")
    return getattr(mod, meta["name"])


def _should_abort(run_id: str) -> bool:
    with ABORT_LOCK:
        return ABORT_FLAGS.get(run_id, False)


def _tail_log(path: Path, stop_event: threading.Event, queue: "list"):
    """Watch a log file and append new lines to `queue` until stop_event set.
    Returns the final offset read."""
    last_size = 0
    while not stop_event.is_set():
        try:
            size = path.stat().st_size
            if size > last_size:
                with open(path, "r", errors="ignore") as f:
                    f.seek(last_size)
                    new_data = f.read()
                last_size = size
                for line in new_data.splitlines():
                    if line.strip():
                        queue.append(line)
        except FileNotFoundError:
            pass
        time.sleep(0.15)
    # final drain
    try:
        size = path.stat().st_size
        if size > last_size:
            with open(path, "r", errors="ignore") as f:
                f.seek(last_size)
                for line in f.read().splitlines():
                    if line.strip():
                        queue.append(line)
    except FileNotFoundError:
        pass


def _read_log(path: Path) -> List[str]:
    """Read all (non-empty) lines from a log file if it exists."""
    try:
        with open(path, "r", errors="ignore") as f:
            return [l for l in f.read().splitlines() if l.strip()]
    except FileNotFoundError:
        return []


def _execute_run(run_id: str, req: RunRequest, log_path: Path):
    """Run the module, capturing logs to log_path, then store the result.

    Log streaming for the live UI is handled by a separate watcher thread in the
    SSE endpoint; this function only runs the module and records the final state.
    """
    meta = MODULE_INDEX.get(req.module_id)
    result_payload: Dict[str, Any] = {}

    # Install a file-backed logger so module output lands in log_path.
    try:
        cls = _load_class(req.module_id)
        logger = setup_logger(cls.__name__, log_file=str(log_path))
        instance = cls()
        instance.logger = logger  # point instance at our logger

        if _should_abort(run_id):
            result_payload = {"aborted": True}
        elif not instance.check_authorization(req.target or "local"):
            result_payload = {"error": "Authorization check failed for target"}
        else:
            results = instance.execute(req.target, **req.options)
            result_payload = {"module": cls.__name__, "results": results}
    except Exception as e:  # capture load/exec errors into the result
        result_payload = {"error": str(e)}

    log_lines = _read_log(log_path)

    # persist results json
    saved_to = None
    if "results" in result_payload:
        config.OUTPUT_DIR.mkdir(exist_ok=True)
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = config.OUTPUT_DIR / f"{result_payload['module']}_{ts}.json"
        with open(out_file, "w") as f:
            json.dump(result_payload["results"], f, indent=2, default=str)
        saved_to = str(out_file)

    record = {
        "run_id": run_id,
        "module_id": req.module_id,
        "module": result_payload.get("module", meta["name"] if meta else req.module_id),
        "target": req.target,
        "options": req.options,
        "status": "aborted" if result_payload.get("aborted") else
                  ("error" if "error" in result_payload else "success"),
        "result": result_payload,
        "log": log_lines,
        "saved_to": saved_to,
        "timestamp": time.time(),
    }
    with RUN_HISTORY_LOCK:
        RUN_HISTORY.insert(0, record)
        del RUN_HISTORY[50:]  # keep last 50


@app.get("/api/modules")
def api_modules():
    return {"modules": MODULES}


@app.get("/api/history")
def api_history():
    slim = [
        {
            "run_id": r["run_id"],
            "module": r["module"],
            "target": r["target"],
            "status": r["status"],
            "timestamp": r["timestamp"],
            "saved_to": r["saved_to"],
        }
        for r in RUN_HISTORY
    ]
    return {"history": slim}


@app.get("/api/history/{run_id}")
def api_history_detail(run_id: str):
    with RUN_HISTORY_LOCK:
        for r in RUN_HISTORY:
            if r["run_id"] == run_id:
                return r
    raise HTTPException(status_code=404, detail="Run not found")


@app.post("/api/abort/{run_id}")
def api_abort(run_id: str):
    with ABORT_LOCK:
        ABORT_FLAGS[run_id] = True
    return {"aborted": True}


@app.post("/api/run")
def api_run(req: RunRequest):
    """Run a module synchronously and return the result (no live stream)."""
    if req.module_id not in MODULE_INDEX:
        raise HTTPException(status_code=404, detail="Module not found")
    run_id = uuid.uuid4().hex[:12]
    log_path = config.LOG_DIR / f"web_{run_id}.log"
    _execute_run(run_id, req, log_path)
    with RUN_HISTORY_LOCK:
        record = next((r for r in RUN_HISTORY if r["run_id"] == run_id), None)
    if record is None:
        raise HTTPException(status_code=500, detail="Run did not produce a record")
    return {
        "run_id": run_id,
        "module": record["module"],
        "status": record["status"],
        "result": record["result"],
        "log": record["log"],
        "saved_to": record["saved_to"],
    }


@app.post("/api/run/stream")
def api_run_stream(req: RunRequest, request: Request):
    """Run a module and stream log lines + final result via SSE."""
    if req.module_id not in MODULE_INDEX:
        raise HTTPException(status_code=404, detail="Module not found")

    run_id = uuid.uuid4().hex[:12]
    log_path = config.LOG_DIR / f"web_{run_id}.log"
    stop = threading.Event()
    log_lines: List[str] = []
    last_sent = 0

    watcher = threading.Thread(
        target=_tail_log, args=(log_path, stop, log_lines), daemon=True
    )
    worker = threading.Thread(
        target=_execute_run, args=(run_id, req, log_path), daemon=True
    )
    watcher.start()
    worker.start()

    def event_gen():
        yield f"event: start\ndata: {json.dumps({'run_id': run_id})}\n\n"
        while worker.is_alive():
            if _should_abort(run_id):
                with ABORT_LOCK:
                    ABORT_FLAGS[run_id] = True
            nonlocal last_sent
            while last_sent < len(log_lines):
                line = log_lines[last_sent]
                last_sent += 1
                yield f"event: log\ndata: {json.dumps({'line': line})}\n\n"
            time.sleep(0.2)
        # drain remaining
        while last_sent < len(log_lines):
            line = log_lines[last_sent]
            last_sent += 1
            yield f"event: log\ndata: {json.dumps({'line': line})}\n\n"
        stop.set()
        # final record
        with RUN_HISTORY_LOCK:
            record = next((r for r in RUN_HISTORY if r["run_id"] == run_id), None)
        if record:
            yield f"event: done\ndata: {json.dumps(record)}\n\n"
        else:
            yield f"event: done\ndata: {json.dumps({'error': 'no record'})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Scope manager: view/edit authorized targets and scope enforcement live.
# ---------------------------------------------------------------------------
@app.get("/api/scope")
def api_get_scope():
    return {
        "scope_enforcement": config.SCOPE_ENFORCEMENT,
        "authorized_targets": list(config.AUTHORIZED_TARGETS),
    }


class ScopeUpdate(BaseModel):
    scope_enforcement: Optional[bool] = None
    authorized_targets: Optional[List[str]] = None


@app.post("/api/scope")
def api_set_scope(u: ScopeUpdate):
    if u.scope_enforcement is not None:
        config.SCOPE_ENFORCEMENT = u.scope_enforcement
    if u.authorized_targets is not None:
        config.AUTHORIZED_TARGETS = list(u.authorized_targets)
    return api_get_scope()


# ---------------------------------------------------------------------------
# Presets / scan profiles: reusable {module_id, options} bundles.
# Persisted to config/presets.json.
# ---------------------------------------------------------------------------
PRESETS_FILE = BASE_DIR / "config" / "presets.json"

DEFAULT_PRESETS = [
    {"name": "Quick Web Audit", "module_id": "vuln_scanner.WebVulnScanner",
     "options": {"check_headers": True, "check_ssl": True}},
    {"name": "Common Port Sweep", "module_id": "recon.PortScanner",
     "options": {"port_range": "1-1024", "scan_type": "tcp"}},
    {"name": "Service Fingerprint", "module_id": "recon.ServiceEnumerator",
     "options": {"ports": "21,22,25,80,443,3306,3389,8080"}},
    {"name": "Password Strength Check", "module_id": "password.PasswordGenerator",
     "options": {"mode": "check"}},
]


def _load_presets() -> List[Dict[str, Any]]:
    if PRESETS_FILE.exists():
        try:
            return json.loads(PRESETS_FILE.read_text())
        except Exception:
            pass
    return [dict(p) for p in DEFAULT_PRESETS]


def _save_presets(presets: List[Dict[str, Any]]):
    PRESETS_FILE.parent.mkdir(exist_ok=True)
    PRESETS_FILE.write_text(json.dumps(presets, indent=2))


@app.get("/api/presets")
def api_get_presets():
    return {"presets": _load_presets()}


class PresetReq(BaseModel):
    name: str
    module_id: str
    options: Dict[str, Any] = {}


@app.post("/api/presets")
def api_add_preset(p: PresetReq):
    if p.module_id not in MODULE_INDEX:
        raise HTTPException(status_code=404, detail="Module not found")
    presets = _load_presets()
    presets.append({"name": p.name, "module_id": p.module_id, "options": p.options})
    _save_presets(presets)
    return {"presets": presets}


@app.delete("/api/presets/{name}")
def api_del_preset(name: str):
    presets = [p for p in _load_presets() if p["name"] != name]
    _save_presets(presets)
    return {"presets": presets}


# ---------------------------------------------------------------------------
# Run queue: execute several modules sequentially against one target.
# Streams progress (per-module start/done) over SSE.
# ---------------------------------------------------------------------------
class QueueRequest(BaseModel):
    target: str = ""
    module_ids: List[str] = []
    options: Dict[str, Dict[str, Any]] = {}  # per-module_id options override


@app.post("/api/queue/run")
def api_queue_run(req: QueueRequest):
    for mid in req.module_ids:
        if mid not in MODULE_INDEX:
            raise HTTPException(status_code=404, detail=f"Unknown module: {mid}")
    run_ids = []

    def event_gen():
        total = len(req.module_ids)
        for i, mid in enumerate(req.module_ids, 1):
            run_id = uuid.uuid4().hex[:12]
            run_ids.append(run_id)
            opts = dict(req.options.get(mid, {}))
            rreq = RunRequest(module_id=mid, target=req.target, options=opts)
            log_path = config.LOG_DIR / f"web_{run_id}.log"
            stop = threading.Event()
            log_lines: List[str] = []
            last_sent = 0
            watcher = threading.Thread(target=_tail_log, args=(log_path, stop, log_lines), daemon=True)
            worker = threading.Thread(target=_execute_run, args=(run_id, rreq, log_path), daemon=True)
            watcher.start(); worker.start()
            yield f"event: module_start\ndata: {json.dumps({'index': i, 'total': total, 'module_id': mid, 'run_id': run_id})}\n\n"
            while worker.is_alive():
                while last_sent < len(log_lines):
                    line = log_lines[last_sent]; last_sent += 1
                    yield f"event: log\ndata: {json.dumps({'run_id': run_id, 'line': line})}\n\n"
                time.sleep(0.2)
            while last_sent < len(log_lines):
                line = log_lines[last_sent]; last_sent += 1
                yield f"event: log\ndata: {json.dumps({'run_id': run_id, 'line': line})}\n\n"
            stop.set()
            with RUN_HISTORY_LOCK:
                rec = next((r for r in RUN_HISTORY if r["run_id"] == run_id), None)
            yield f"event: module_done\ndata: {json.dumps({'index': i, 'total': total, 'record': rec})}\n\n"
        yield f"event: queue_done\ndata: {json.dumps({'run_ids': run_ids})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Report export: feed a past run's results into the reporting module.
# ---------------------------------------------------------------------------
@app.post("/api/report/{run_id}")
def api_report(run_id: str, fmt: str = "html"):
    with RUN_HISTORY_LOCK:
        rec = next((r for r in RUN_HISTORY if r["run_id"] == run_id), None)
    if not rec:
        raise HTTPException(status_code=404, detail="Run not found")
    results = rec.get("result", {}).get("results")
    if results is None:
        raise HTTPException(status_code=400, detail="Run has no results to report")
    try:
        from modules.reporting.report_generator import ReportGenerator
        gen = ReportGenerator()
        gen.logger = setup_logger("ReportGenerator", log_file=str(config.LOG_DIR / f"web_report_{run_id}.log"))
        out = gen.execute(rec.get("target", "unknown"), results=results, format=fmt)
        path = out.get("report_path") or out.get("output_path")
        return {"report": out, "path": path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/disclaimer")
def api_disclaimer():
    return {"disclaimer": config.DISCLAIMER}


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def main():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
