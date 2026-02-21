"""
Monitoring Dashboard

FastAPI app serving:
  GET  /                → interactive HTML dashboard
  GET  /api/tasks       → recent tasks
  GET  /api/logs        → audit log entries
  GET  /api/stats       → platform stats
  POST /api/analyze     → trigger analysis
  POST /api/hitl/{id}   → submit HITL decision
  GET  /api/iac/{id}    → download IaC bundle for a task
  WS   /ws              → real-time event stream
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import zipfile
import io
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)

app = FastAPI(title="Secure Analysis Platform", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

MAX_EVENTS = 1000
_events: Deque[Dict] = deque(maxlen=MAX_EVENTS)
_active_tasks: Dict[str, Dict] = {}
_ws_clients: List[WebSocket] = []
_stats = {"total_tasks": 0, "approved": 0, "rejected": 0,
          "hitl_escalated": 0, "start_time": time.time()}

# Store IaC bundles keyed by task_id for download
_iac_store: Dict[str, Dict] = {}

# Pending HITL requests/alerts keyed by alert_id
_pending_hitl: Dict[str, Dict] = {}

# Intelligence summaries keyed by task_id
_intelligence_store: Dict[str, Dict] = {}


async def _broadcast(event: Dict) -> None:
    event.setdefault("timestamp", time.time())
    _events.appendleft(event)
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


def add_event(event_type: str, data: Dict, severity: str = "info") -> None:
    """Called from main.py pipeline stages."""
    event = {"type": event_type, "severity": severity, "data": data,
             "timestamp": time.time()}

    # Cache IaC contents when stage completes
    if event_type == "stage_update" and data.get("stage") == "iac" and data.get("status") == "complete":
        task_id = data.get("task_id")
        if task_id:
            _iac_store[task_id] = {
                "terraform": data.get("terraform_contents", {}),
                "ansible": data.get("ansible_contents", {}),
                "method": data.get("method", "declarative"),
                "generated_at": time.time(),
            }

    # Cache intelligence summaries
    if event_type == "intelligence_ready":
        task_id = data.get("task_id")
        if task_id:
            _intelligence_store[task_id] = data.get("summary", {})

    # Cache HITL alerts (new format from real pipeline)
    if event_type == "hitl_alert":
        alert_id = data.get("alert_id")
        if alert_id:
            _pending_hitl[alert_id] = {**data, "status": "pending"}

    # Cache HITL requests (old format — backward compat)
    if event_type == "hitl_required":
        req_id = data.get("hitl_request_id")
        if req_id:
            _pending_hitl[req_id] = {**data, "status": "pending"}

    # Track VM events per task
    if event_type == "vm_created":
        task_id = data.get("task_id")
        if task_id and task_id in _active_tasks:
            vms = _active_tasks[task_id].setdefault("vms", {})
            vms[data.get("vm_id", "")] = {
                "role": data.get("role"), "ip": data.get("private_ip"),
                "name": data.get("azure_name"), "status": "running",
                "created_at": time.time(),
            }
    if event_type == "vm_terminated":
        task_id = data.get("task_id")
        if task_id and task_id in _active_tasks:
            vms = _active_tasks[task_id].get("vms", {})
            vm_id = data.get("vm_id", "")
            if vm_id in vms:
                vms[vm_id]["status"] = data.get("reason", "terminated")

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(_broadcast(event))
        else:
            _events.appendleft(event)
    except RuntimeError:
        _events.appendleft(event)


# ── Wire pipeline callback ────────────────────────────────────────

@app.on_event("startup")
async def _wire_pipeline() -> None:
    try:
        from src.main import set_ui_callback
        set_ui_callback(add_event)
    except Exception:
        pass


# ── REST API ──────────────────────────────────────────────────────

@app.get("/api/events")
async def get_events(limit: int = 200) -> List[Dict]:
    return list(_events)[:limit]


@app.get("/api/tasks")
async def get_tasks() -> Dict:
    return {"tasks": list(_active_tasks.values()), "stats": _stats}


@app.get("/api/logs")
async def get_logs(limit: int = 200) -> List[Dict]:
    try:
        from logs.audit import get_audit
        return get_audit().get_recent(limit)
    except Exception:
        return []


@app.get("/api/stats")
async def get_stats() -> Dict:
    return _stats


@app.get("/api/health")
async def health() -> Dict:
    return {"status": "healthy", "uptime": time.time() - _stats["start_time"],
            "active_tasks": len([t for t in _active_tasks.values()
                                 if t.get("status") == "running"])}


@app.post("/api/analyze")
async def trigger_analysis(request: Dict[str, Any]) -> Dict:
    repo_url = request.get("repo_url", "").strip()
    if not repo_url:
        return {"error": "repo_url required"}

    import secrets as _s
    task_id = _s.token_hex(8)
    _active_tasks[task_id] = {
        "task_id": task_id, "repo_url": repo_url,
        "status": "running", "started_at": time.time(),
        "stages": {},
    }
    _stats["total_tasks"] += 1
    asyncio.create_task(_run_task(task_id, repo_url))
    return {"task_id": task_id, "status": "started"}


@app.get("/api/iac/{task_id}")
async def download_iac(task_id: str, fmt: str = "zip") -> StreamingResponse:
    """Download IaC bundle for a completed task as a zip file."""
    bundle = _iac_store.get(task_id)
    if not bundle:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="IaC bundle not found for this task")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in bundle.get("terraform", {}).items():
            zf.writestr(f"terraform/{fname}", content)
        for fname, content in bundle.get("ansible", {}).items():
            zf.writestr(f"ansible/{fname}", content)
        # Add a README
        readme = f"""# IaC Bundle — Task {task_id}
Method: {bundle.get('method', 'unknown')}
Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bundle.get('generated_at', 0)))}

## Terraform files
{chr(10).join('- terraform/' + f for f in bundle.get('terraform', {}))}

## Ansible files
{chr(10).join('- ansible/' + f for f in bundle.get('ansible', {}))}

## Usage
```bash
cd terraform/
terraform init
terraform plan
terraform apply

cd ../ansible/
ansible-playbook site.yml
```
"""
        zf.writestr("README.md", readme)

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=iac-bundle-{task_id[:8]}.zip"},
    )


@app.get("/api/iac/{task_id}/file")
async def download_iac_file(task_id: str, path: str) -> StreamingResponse:
    """Download a single IaC file."""
    bundle = _iac_store.get(task_id)
    if not bundle:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="IaC bundle not found")

    # path like "terraform/main.tf" or "ansible/site.yml"
    parts = path.split("/", 1)
    if len(parts) == 2:
        section, fname = parts
        files = bundle.get(section, {})
        content = files.get(fname)
        if content is not None:
            filename = fname.replace("/", "_")
            return StreamingResponse(
                io.BytesIO(content.encode()),
                media_type="text/plain",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail=f"File not found: {path}")


@app.get("/api/hitl")
async def list_hitl() -> List[Dict]:
    """List all HITL alerts (malicious files + policy confidence)."""
    return list(_pending_hitl.values())


@app.get("/api/intelligence/{task_id}")
async def get_intelligence(task_id: str) -> Dict:
    """Get intelligence summary for a task."""
    intel = _intelligence_store.get(task_id)
    if not intel:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Intelligence summary not ready")
    return intel


@app.get("/api/vms")
async def get_active_vms() -> List[Dict]:
    """Get all active VMs across all tasks."""
    try:
        from src.main import get_pipeline
        return get_pipeline()._orchestrator.list_active_vms()
    except Exception:
        return []


@app.post("/api/hitl/{alert_id}")
async def submit_hitl(alert_id: str, body: Dict[str, Any]) -> Dict:
    """
    Submit a HITL decision for a security alert or policy escalation.
    decision: APPROVE | REJECT | QUARANTINE
    """
    if alert_id not in _pending_hitl:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")

    decision    = body.get("decision", "").upper()
    operator_id = body.get("operator_id", "human-operator")
    notes       = body.get("notes", "")

    if decision not in ("APPROVE", "REJECT", "QUARANTINE"):
        return {"error": "decision must be APPROVE, REJECT, or QUARANTINE"}

    alert = _pending_hitl[alert_id]
    alert["status"]      = "resolved"
    alert["decision"]    = decision
    alert["operator_id"] = operator_id
    alert["notes"]       = notes
    alert["resolved_at"] = time.time()

    task_id = alert.get("task_id", "")
    add_event("hitl_resolved", {
        "task_id":    task_id,
        "alert_id":   alert_id,
        "type":       alert.get("type", "unknown"),
        "decision":   decision,
        "operator_id": operator_id,
        "notes":      notes,
        "message": (
            f"✅ HITL resolved: {decision} by {operator_id}"
            + (f" — {notes}" if notes else "")
        ),
    }, severity="info" if decision == "APPROVE" else "warning")

    # Also forward to pipeline policy engine if it's a policy escalation
    if alert.get("type") == "policy_confidence":
        try:
            from src.main import get_pipeline
            from src.schemas.a2a_schemas import (
                AgentRole, HITLResponse, MessageType, create_header,
            )
            pipeline = get_pipeline()
            header = create_header(
                MessageType.HITL_RESPONSE,
                AgentRole.HITL_ESCALATION,
                AgentRole.POLICY_ENGINE,
                task_id,
            )
            response = HITLResponse(
                header=header,
                request_id=alert_id,
                decision=decision,
                operator_id=operator_id,
                notes=notes,
            )
            await pipeline.policy_engine._hitl_responses.put(response)
        except Exception as e:
            logger.warning("Could not forward HITL to policy engine: %s", e)

    # Notify pipeline of malicious file resolution
    try:
        from src.main import resolve_hitl_alert
        resolve_hitl_alert(alert_id, decision, operator_id, notes)
    except Exception:
        pass

    return {"status": "ok", "decision": decision, "alert_id": alert_id}


async def _run_task(task_id: str, repo_url: str) -> None:
    try:
        from src.main import get_pipeline
        pipeline = get_pipeline()
        result = await pipeline.run_analysis(repo_url, task_id)

        decision = result.get("decision", "UNKNOWN")
        if decision == "APPROVE":
            _stats["approved"] += 1
        elif decision == "REJECT":
            _stats["rejected"] += 1
        if result.get("hitl_required"):
            _stats["hitl_escalated"] += 1

        _active_tasks[task_id] = {**_active_tasks.get(task_id, {}), **result,
                                   "status": "complete"}
    except Exception as e:
        logger.error("Task %s failed: %s", task_id, e)
        _active_tasks[task_id] = {**_active_tasks.get(task_id, {}),
                                   "status": "failed", "error": str(e)}
        add_event("task_failed", {"task_id": task_id, "error": str(e),
                                   "message": f"Task failed: {e}"}, "error")


# ── WebSocket ──────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    _ws_clients.append(ws)
    try:
        await ws.send_json({
            "type": "init",
            "data": {
                "events": list(_events)[:100],
                "stats": _stats,
                "tasks": list(_active_tasks.values()),
                "pending_hitl": list(_pending_hitl.values()),
            },
            "timestamp": time.time(),
        })
        while True:
            msg = await asyncio.wait_for(ws.receive_text(), timeout=30)
            if msg == "ping":
                await ws.send_json({"type": "pong", "timestamp": time.time()})
    except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
        pass
    finally:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ── HTML Dashboard ─────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Secure Analysis Platform</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
    :root {
      --bg:#0b0e14; --surface:#111520; --surface2:#181d2a; --border:#1e2538;
      --text:#cdd6f4; --muted:#6c7086; --subtle:#313552;
      --green:#a6e3a1; --red:#f38ba8; --yellow:#f9e2af; --blue:#89b4fa;
      --purple:#cba6f7; --orange:#fab387; --teal:#94e2d5; --sky:#89dceb;
      --green-dim:#2a3d2a; --red-dim:#3d1f1f; --yellow-dim:#3a3020; --blue-dim:#1a2a3d;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    body{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;font-size:13px;min-height:100vh;overflow-x:hidden;}
    code,pre,.mono{font-family:'IBM Plex Mono',monospace;}

    .hdr{background:var(--surface);border-bottom:1px solid var(--border);padding:10px 20px;
        display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100;}
    .hdr-logo{display:flex;align-items:center;gap:8px;}
    .hdr-title{font-weight:700;font-size:15px;letter-spacing:-.3px;}
    .hdr-sub{font-size:11px;color:var(--muted);}
    .ws-badge{margin-left:auto;font-size:11px;padding:3px 8px;border-radius:99px;
              border:1px solid currentColor;font-family:'IBM Plex Mono',monospace;}
    .ws-connected{color:var(--green);}
    .ws-disconnected{color:var(--red);}

    .layout{display:grid;grid-template-columns:340px 1fr 300px;gap:1px;background:var(--border);height:calc(100vh - 45px);}
    .panel{background:var(--bg);display:flex;flex-direction:column;overflow:hidden;}
    .panel-hdr{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;
              align-items:center;gap:8px;font-size:11px;font-weight:600;letter-spacing:.8px;
              text-transform:uppercase;color:var(--muted);flex-shrink:0;}
    .panel-hdr .badge{margin-left:auto;background:var(--surface2);padding:2px 7px;
                      border-radius:99px;font-size:10px;color:var(--text);}
    .panel-body{flex:1;overflow-y:auto;padding:12px;}
    .panel-body::-webkit-scrollbar{width:4px;}
    .panel-body::-webkit-scrollbar-thumb{background:var(--subtle);border-radius:2px;}

    .input-bar{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px;flex-shrink:0;}
    .input-bar input{flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--text);
                    padding:7px 12px;border-radius:6px;font-size:12px;font-family:inherit;outline:none;}
    .input-bar input:focus{border-color:var(--blue);}
    .input-bar input::placeholder{color:var(--muted);}
    .btn{padding:7px 14px;border-radius:6px;border:none;cursor:pointer;font-size:12px;
        font-family:inherit;font-weight:600;transition:.15s;}
    .btn-blue{background:var(--blue);color:#000;}
    .btn-blue:hover{opacity:.85;}
    .btn-green{background:var(--green);color:#000;}
    .btn-green:hover{opacity:.85;}
    .btn-red{background:var(--red);color:#000;}
    .btn-red:hover{opacity:.85;}
    .btn-sm{padding:4px 10px;font-size:11px;border-radius:4px;}

    .stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px;}
    .stat-box{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 12px;}
    .stat-val{font-size:22px;font-weight:700;font-family:'IBM Plex Mono',monospace;margin-bottom:2px;}
    .stat-lbl{font-size:10px;color:var(--muted);letter-spacing:.5px;text-transform:uppercase;}
    .stat-green{color:var(--green);}
    .stat-red{color:var(--red);}
    .stat-blue{color:var(--blue);}
    .stat-yellow{color:var(--yellow);}

    .pipeline{display:flex;align-items:center;gap:0;overflow-x:auto;padding:4px 0 8px;margin-bottom:12px;}
    .pip-stage{display:flex;flex-direction:column;align-items:center;gap:3px;padding:8px 10px;
              border:1px solid var(--border);background:var(--surface);cursor:default;
              min-width:64px;position:relative;transition:.2s;}
    .pip-stage:not(:last-child)::after{content:'›';position:absolute;right:-10px;
      color:var(--muted);font-size:14px;z-index:1;}
    .pip-stage+.pip-stage{margin-left:8px;}
    .pip-icon{font-size:16px;}
    .pip-name{font-size:9px;color:var(--muted);letter-spacing:.5px;text-transform:uppercase;}
    .pip-stage.running{border-color:var(--blue);background:var(--blue-dim);}
    .pip-stage.running .pip-name{color:var(--blue);}
    .pip-stage.complete{border-color:var(--green);background:var(--green-dim);}
    .pip-stage.complete .pip-name{color:var(--green);}
    .pip-stage.error{border-color:var(--red);background:var(--red-dim);}
    .pip-stage.error .pip-name{color:var(--red);}

    .task-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
              padding:10px 12px;margin-bottom:8px;}
    .task-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;}
    .task-id{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--sky);}
    .task-repo{font-size:11px;color:var(--muted);margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .badge-small{padding:2px 7px;border-radius:99px;font-size:9px;font-weight:700;letter-spacing:.5px;}
    .bg-green{background:var(--green-dim);color:var(--green);}
    .bg-red{background:var(--red-dim);color:var(--red);}
    .bg-yellow{background:var(--yellow-dim);color:var(--yellow);}
    .bg-blue{background:var(--blue-dim);color:var(--blue);}
    .bg-muted{background:var(--surface2);color:var(--muted);}
    .risk-bar{height:3px;border-radius:2px;margin-top:4px;}
    .risk-low{background:var(--green);}
    .risk-med{background:var(--yellow);}
    .risk-high{background:var(--orange);}
    .risk-crit{background:var(--red);}

    .vm-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;}
    .vm-card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:7px 9px;}
    .vm-card.terminated{opacity:.45;}
    .vm-role{font-size:10px;font-weight:600;letter-spacing:.3px;text-transform:uppercase;
            margin-bottom:3px;display:flex;align-items:center;gap:5px;}
    .vm-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;}
    .vm-dot.running{background:var(--green);animation:blink 1.5s ease infinite;}
    .vm-dot.terminated{background:var(--muted);}
    @keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
    .vm-id{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);}
    .vm-ip{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--teal);}

    .log-entry{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);
              align-items:flex-start;font-size:11px;font-family:'IBM Plex Mono',monospace;}
    .log-entry:last-child{border-bottom:none;}
    .log-time{color:var(--muted);flex-shrink:0;width:68px;}
    .log-sev{flex-shrink:0;width:54px;text-align:center;border-radius:3px;
            padding:1px 4px;font-size:9px;font-weight:700;letter-spacing:.5px;}
    .sev-info{background:var(--blue-dim);color:var(--blue);}
    .sev-success{background:var(--green-dim);color:var(--green);}
    .sev-warning{background:var(--yellow-dim);color:var(--yellow);}
    .sev-error{background:var(--red-dim);color:var(--red);}
    .log-msg{flex:1;color:var(--text);line-height:1.4;word-break:break-word;}
    .log-msg .stage-tag{color:var(--purple);margin-right:4px;}
    .log-msg .task-tag{color:var(--sky);margin-right:4px;}

    /* IaC panel */
    .iac-panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;
              margin-bottom:8px;overflow:hidden;}
    .iac-head{padding:7px 12px;background:var(--surface2);border-bottom:1px solid var(--border);
              display:flex;align-items:center;gap:8px;font-size:11px;font-weight:600;}
    .iac-head .iac-fname{flex:1;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--sky);}
    .iac-body{padding:10px 12px;font-family:'IBM Plex Mono',monospace;font-size:10px;
              color:var(--muted);max-height:140px;overflow-y:auto;line-height:1.6;white-space:pre-wrap;}
    .download-btn{padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);
                  color:var(--blue);font-size:10px;cursor:pointer;font-family:inherit;white-space:nowrap;}
    .download-btn:hover{background:var(--blue-dim);}

    /* HITL panel */
    .hitl-card{background:#1a1200;border:2px solid var(--yellow);border-radius:8px;padding:12px;margin-bottom:10px;}
    .hitl-title{color:var(--yellow);font-weight:700;font-size:12px;margin-bottom:6px;}
    .hitl-info{font-size:11px;color:var(--muted);margin-bottom:8px;line-height:1.6;}
    .hitl-actions{display:flex;gap:8px;}

    .empty{text-align:center;color:var(--muted);padding:24px;font-size:12px;}

    /* ── Resource Map ──────────────────────────────────────────────────── */
    .res-map{position:relative;background:var(--surface);border:1px solid var(--border);
            border-radius:10px;margin-bottom:12px;overflow:hidden;min-height:220px;
            font-family:'IBM Plex Mono',monospace;}
    .res-map-title{padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:.8px;
                  text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);
                  display:flex;align-items:center;justify-content:space-between;}
    .res-map-title span{color:var(--blue);}
    .res-map-body{padding:12px 14px;position:relative;}

    /* Resource group frame */
    .rg-frame{border:1px dashed #313552;border-radius:8px;padding:10px;position:relative;
              background:rgba(30,37,56,0.4);}
    .rg-label{position:absolute;top:-9px;left:12px;background:var(--surface);
              padding:0 6px;font-size:9px;color:var(--muted);letter-spacing:.5px;white-space:nowrap;}

    /* VNet frame inside RG */
    .vnet-frame{border:1px dashed #1e4a7a;border-radius:6px;padding:8px;position:relative;
                margin-top:6px;background:rgba(137,180,250,0.03);}
    .vnet-label{position:absolute;top:-8px;left:10px;background:var(--surface);
                padding:0 5px;font-size:9px;color:var(--blue);letter-spacing:.3px;white-space:nowrap;}

    /* Subnet frame inside VNet */
    .subnet-frame{border:1px solid #1e2538;border-radius:5px;padding:8px;position:relative;
                  background:rgba(20,25,40,0.5);min-height:52px;}
    .subnet-label{position:absolute;top:-8px;left:8px;background:var(--surface);
                  padding:0 5px;font-size:9px;color:var(--teal);letter-spacing:.3px;white-space:nowrap;}

    /* NSG badge — floats top-right of RG frame */
    .nsg-badge{position:absolute;top:8px;right:8px;border:1px solid var(--red);
                border-radius:5px;padding:4px 8px;font-size:9px;display:flex;
                align-items:center;gap:4px;background:rgba(243,139,168,0.05);}
    .nsg-badge.active{border-color:var(--red);color:var(--red);}
    .nsg-badge.inactive{border-color:var(--muted);color:var(--muted);}

    /* KeyVault badge */
    .kv-badge{position:absolute;bottom:8px;right:8px;border:1px solid var(--purple);
              border-radius:5px;padding:4px 8px;font-size:9px;display:flex;
              align-items:center;gap:4px;background:rgba(203,166,247,0.05);color:var(--purple);}

    /* Resource node inside subnet */
    .res-nodes{display:flex;flex-wrap:wrap;gap:5px;align-items:center;min-height:38px;}
    .res-node{display:flex;align-items:center;gap:4px;border-radius:5px;padding:4px 8px;
              font-size:9px;border:1px solid;transition:all .3s ease;position:relative;
              cursor:default;white-space:nowrap;}
    .res-node.spawning{animation:nodeSpawn .4s ease;}
    .res-node.running{opacity:1;}
    .res-node.terminated{opacity:.35;filter:grayscale(1);text-decoration:line-through;}
    .res-node .res-dot{width:5px;height:5px;border-radius:50%;flex-shrink:0;}
    .res-node.running .res-dot{animation:blink 1.4s ease infinite;}
    .res-node .res-name{font-family:'IBM Plex Mono',monospace;font-size:8px;max-width:90px;
                        overflow:hidden;text-overflow:ellipsis;}

    /* Destroyed overlay */
    .res-map.destroyed .rg-frame{border-color:#f38ba833;opacity:.5;}
    .res-map.destroyed .vnet-frame{border-color:#f38ba822;}
    .res-map-destroyed-banner{display:none;position:absolute;inset:0;background:rgba(11,14,20,.75);
      z-index:10;align-items:center;justify-content:center;flex-direction:column;gap:6px;
      border-radius:10px;font-size:12px;color:var(--red);font-weight:700;letter-spacing:.5px;}
    .res-map.destroyed .res-map-destroyed-banner{display:flex;}

    /* Tooltip */
    .res-node:hover::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 4px);
      left:50%;transform:translateX(-50%);background:#0b0e14;border:1px solid var(--border);
      border-radius:4px;padding:4px 8px;font-size:9px;white-space:nowrap;z-index:20;
      color:var(--text);pointer-events:none;}

    @keyframes nodeSpawn{0%{transform:scale(.6);opacity:0}60%{transform:scale(1.08)}100%{transform:scale(1);opacity:1}}
</style>
</head>
<body>
<div class="hdr">
  <div class="hdr-logo">
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
      <rect width="22" height="22" rx="4" fill="#1e2538"/>
      <path d="M11 4L18 8V14L11 18L4 14V8L11 4Z" stroke="#89b4fa" stroke-width="1.5" fill="none"/>
      <circle cx="11" cy="11" r="2.5" fill="#a6e3a1"/>
    </svg>
    <div>
      <div class="hdr-title">Secure Analysis Platform</div>
      <div class="hdr-sub">Zero-trust · mTLS · AES-256 · Ephemeral µVMs</div>
    </div>
  </div>
  <span id="ws-status" class="ws-badge ws-disconnected">● disconnected</span>
</div>

<div class="layout">

  <!-- LEFT: input + stats + task list -->
  <div class="panel">
    <div class="input-bar">
      <input id="repo-url" type="text" placeholder="https://github.com/owner/repo" />
      <button class="btn btn-blue" onclick="analyze()">Analyze</button>
    </div>
    <div class="panel-body">
      <div class="stats-row">
        <div class="stat-box"><div class="stat-val stat-blue" id="s-total">0</div><div class="stat-lbl">Total</div></div>
        <div class="stat-box"><div class="stat-val stat-green" id="s-approved">0</div><div class="stat-lbl">Approved</div></div>
        <div class="stat-box"><div class="stat-val stat-red" id="s-rejected">0</div><div class="stat-lbl">Rejected</div></div>
        <div class="stat-box"><div class="stat-val stat-yellow" id="s-hitl">0</div><div class="stat-lbl">HITL</div></div>
      </div>

      <!-- HITL pending panel -->
      <div id="hitl-panel" style="display:none;margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:var(--yellow);margin-bottom:6px;letter-spacing:.5px;">⚠️ HUMAN-IN-THE-LOOP REQUIRED</div>
        <div id="hitl-requests"></div>
      </div>

      <div class="panel-hdr" style="padding:0 0 8px;border:none;">🔁 Pipeline <span class="badge" id="task-count">0</span></div>
      <div id="task-list"><div class="empty">Enter a GitHub URL to start analysis</div></div>
    </div>
  </div>

  <!-- CENTER: pipeline + IaC preview -->
  <div class="panel">

    <!-- Azure Resource Map -->
    <div style="padding:10px 14px 0;flex-shrink:0;">
      <div class="res-map" id="res-map">
        <div class="res-map-title">
          ☁️ Azure Resource Map
          <span id="res-map-status">idle</span>
        </div>
        <div class="res-map-body">
          <!-- Destroyed overlay -->
          <div class="res-map-destroyed-banner">
            🗑️ ENVIRONMENT DESTROYED<br>
            <span style="font-size:9px;color:var(--muted);font-weight:400">Audit log preserved · All ACIs deleted</span>
          </div>

          <!-- Resource Group frame -->
          <div class="rg-frame" id="rg-frame">
            <div class="rg-label" id="rg-label">📦 Resource Group · <span id="rg-name">—</span></div>

            <!-- NSG badge top-right -->
            <div class="nsg-badge inactive" id="nsg-badge">
              <span>🛡️</span><span id="nsg-name">NSG</span>
            </div>

            <!-- VNet frame -->
            <div class="vnet-frame" id="vnet-frame">
              <div class="vnet-label">🌐 VNet · <span id="vnet-name">—</span></div>

              <!-- Subnet frame -->
              <div class="subnet-frame">
                <div class="subnet-label">🔗 Subnet 10.0.1.0/24</div>
                <div class="res-nodes" id="res-nodes">
                  <div style="color:var(--muted);font-size:9px;padding:4px;">Waiting for containers...</div>
                </div>
              </div>
            </div>

            <!-- Key Vault badge bottom-right -->
            <div class="kv-badge" id="kv-badge" style="display:none;">
              🔑 <span id="kv-name">Key Vault</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Pipeline stages -->
    <div style="padding:4px 14px 0;flex-shrink:0;overflow-x:auto;">
      <div class="pipeline">
        <div class="pip-stage" id="pip-fetch"><div class="pip-icon">🌐</div><div class="pip-name">Fetch</div></div>
        <div class="pip-stage" id="pip-parse"><div class="pip-icon">🌳</div><div class="pip-name">Parse</div></div>
        <div class="pip-stage" id="pip-ir"><div class="pip-icon">⚙️</div><div class="pip-name">IR Build</div></div>
        <div class="pip-stage" id="pip-ml"><div class="pip-icon">🤖</div><div class="pip-name">ML Score</div></div>
        <div class="pip-stage" id="pip-policy"><div class="pip-icon">⚖️</div><div class="pip-name">Policy</div></div>
        <div class="pip-stage" id="pip-strategy"><div class="pip-icon">🗺️</div><div class="pip-name">Strategy</div></div>
        <div class="pip-stage" id="pip-iac"><div class="pip-icon">📄</div><div class="pip-name">IaC Gen</div></div>
        <div class="pip-stage" id="pip-deploy"><div class="pip-icon">🚀</div><div class="pip-name">Deploy</div></div>
      </div>
    </div>

    <!-- Stage detail -->
    <div style="padding:0 14px;flex-shrink:0;margin-bottom:8px;">
      <div id="stage-detail" style="background:var(--surface);border:1px solid var(--border);
           border-radius:8px;padding:10px 14px;min-height:44px;font-size:12px;color:var(--muted);">
        Awaiting analysis...
      </div>
    </div>

    <!-- IaC preview + downloads -->
    <div id="iac-preview" style="display:none;flex:1;overflow-y:auto;padding:0 14px 14px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <div style="font-size:11px;font-weight:700;color:var(--text);letter-spacing:.5px;">📋 GENERATED IaC FILES</div>
        <button class="btn btn-blue btn-sm" id="dl-all-btn" onclick="downloadAll()">⬇ Download All (.zip)</button>
      </div>
      <div id="iac-files"></div>
    </div>

  </div>

  <!-- RIGHT: VMs + Audit Log -->
  <div class="panel">
    <div class="panel-hdr">💻 µVMs <span class="badge" id="vm-count">0</span></div>
    <div style="padding:10px;flex-shrink:0;border-bottom:1px solid var(--border);">
      <div class="vm-grid" id="vm-grid"><div class="empty" style="grid-column:span 2;">No active VMs</div></div>
    </div>
    <div class="panel-hdr">📋 Audit Log <span class="badge" id="log-count">0</span></div>
    <div class="panel-body" id="log-panel"></div>
  </div>

</div>

<script>
let ws = null;
let stats = {total_tasks:0, approved:0, rejected:0, hitl_escalated:0};
let tasks = [];
let vms = {};
let logs = [];
let currentTask = null;
let currentTaskId = null;
let pipelineState = {};
let iacContents = {terraform:{}, ansible:{}, method:''};
let pendingHitl = {};

const STAGE_MAP = {
  fetch:'pip-fetch', parse:'pip-parse', ir:'pip-ir', ml:'pip-ml',
  policy:'pip-policy', strategy:'pip-strategy', iac:'pip-iac', deploy:'pip-deploy',
};
const ROLE_COLORS = {
  secure_fetcher:'#89b4fa', ast_parser:'#a6e3a1', ir_builder:'#cba6f7',
  ml_analyzer:'#fab387', policy_engine:'#f9e2af', strategy_agent:'#94e2d5',
  iac_generator:'#89dceb', deployment_agent:'#f38ba8',
};

/* ── WebSocket ── */
function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);
  ws.onopen = () => setWS(true);
  ws.onclose = () => { setWS(false); setTimeout(connect, 2500); };
  ws.onmessage = e => handle(JSON.parse(e.data));
  setInterval(() => ws?.readyState === 1 && ws.send('ping'), 20000);
}

function setWS(ok) {
  const el = document.getElementById('ws-status');
  el.textContent = ok ? '● connected' : '● disconnected';
  el.className = 'ws-badge ' + (ok ? 'ws-connected' : 'ws-disconnected');
}

function handle(msg) {
  if (msg.type === 'init') {
    stats = msg.data.stats || stats;
    (msg.data.tasks || []).forEach(t => { tasks.unshift(t); currentTask = t; });
    (msg.data.events || []).forEach(e => processEvent(e, false));
    (msg.data.pending_hitl || []).forEach(h => { if(h.status==='pending') pendingHitl[h.hitl_request_id]=h; });
    renderAll(); return;
  }
  processEvent(msg, true);
  renderAll();
}

function processEvent(ev, live) {
  const d = ev.data || {};
  const tid = d.task_id;

  logs.unshift({...ev, _id: Math.random()});
  if (logs.length > 300) logs.length = 300;

  switch (ev.type) {
    case 'task_started':
      currentTask = {task_id:tid, repo_url:d.repo_url, status:'running', started_at:ev.timestamp};
      currentTaskId = tid;
      pipelineState = {};
      iacContents = {terraform:{}, ansible:{}, method:''};
      resetPipeline();
      break;

    case 'stage_update': {
      const stage = d.stage;
      if (STAGE_MAP[stage]) {
        pipelineState[stage] = d.status;
        setStage(STAGE_MAP[stage], d.status);
      }
      setDetail(d);

      // Feed network bootstrap info into the resource map
      if (stage === 'network' && d.status === 'complete') {
        mapBootstrap(d.vnet, d.nsg);
      }
      if (stage === 'network' && d.status === 'running') {
        mapSetStatus('provisioning…');
      }
      if (stage === 'iac' && d.status === 'complete') {
        iacContents = {
          terraform: d.terraform_contents || {},
          ansible: d.ansible_contents || {},
          method: d.method || '',
          task_id: tid,
        };
        showIaC(d);
      }
      if (currentTask) currentTask.last_stage = stage;
      break;
    }

    case 'hitl_required':
      pendingHitl[d.hitl_request_id] = {...d, status:'pending'};
      renderHitl();
      break;

    case 'hitl_resolved':
      if (pendingHitl[d.hitl_request_id]) {
        pendingHitl[d.hitl_request_id].status = 'resolved';
      }
      renderHitl();
      break;

    case 'vm_created':
      vms[d.vm_id] = {...d, status:'running', created_at: ev.timestamp || Date.now()/1000};
      mapAddNode(d.vm_id, d.role, d.azure_name, d.private_ip);
      break;
    case 'vm_terminated':
      if (vms[d.vm_id]) vms[d.vm_id].status = 'terminated';
      mapTerminateNode(d.vm_id, d.reason);
      break;

    case 'environment_teardown':
      Object.values(vms).forEach(v => v.status = 'terminated');
      mapTeardown();
      setDetail({message:'🧹 Ephemeral environment destroyed — audit log preserved.'});
      break;

    case 'task_complete':
      if (currentTask) Object.assign(currentTask, d, {status:'complete'});
      const existing = tasks.findIndex(t => t.task_id === tid);
      if (existing >= 0) Object.assign(tasks[existing], d, {status:'complete'});
      else tasks.unshift({...d, status:'complete'});
      if (d.decision === 'APPROVE') stats.approved = (stats.approved||0)+1;
      else if (d.decision === 'REJECT') stats.rejected = (stats.rejected||0)+1;
      if (d.hitl_required) stats.hitl_escalated = (stats.hitl_escalated||0)+1;
      tasks = tasks.slice(0,20);
      if (d.decision === 'REJECT') setAllStages('error');
      // Update IaC contents from task_complete event too
      if (d.terraform_contents) {
        iacContents = {
          terraform: d.terraform_contents || {},
          ansible: d.ansible_contents || {},
          method: d.deployment_method || '',
          task_id: tid,
        };
      }
      break;

    case 'task_failed':
      setAllStages('error');
      setDetail({message:`❌ Task failed: ${d.error||'Unknown error'}`, stage:'failed', status:'error'});
      break;
  }
}

/* ── Pipeline UI ── */
function resetPipeline() {
  Object.values(STAGE_MAP).forEach(id => setStage(id, 'idle'));
  document.getElementById('iac-preview').style.display = 'none';
  document.getElementById('iac-files').innerHTML = '';
  document.getElementById('stage-detail').textContent = 'Starting analysis...';
  const map = document.getElementById('res-map');
  if (map) map.classList.remove('destroyed');
  const nodes = document.getElementById('res-nodes');
  if (nodes) nodes.innerHTML = '<div data-placeholder style="color:var(--muted);font-size:9px;padding:4px;">Waiting for containers...</div>';
  const vnetName = document.getElementById('vnet-name');
  if (vnetName) vnetName.textContent = '—';
  const rgName = document.getElementById('rg-name');
  if (rgName) rgName.textContent = '—';
  const nsgBadge = document.getElementById('nsg-badge');
  if (nsgBadge) nsgBadge.className = 'nsg-badge inactive';
  const kvBadge = document.getElementById('kv-badge');
  if (kvBadge) kvBadge.style.display = 'none';
  mapSetStatus('idle');
}

function setStage(pipId, status) {
  const el = document.getElementById(pipId);
  if (!el) return;
  el.className = 'pip-stage ' + (
    status === 'running' ? 'running' :
    status === 'complete' ? 'complete' :
    status === 'error' ? 'error' : '');
}

function setAllStages(status) {
  Object.values(STAGE_MAP).forEach(id => setStage(id, status));
}

function setDetail(d) {
  const el = document.getElementById('stage-detail');
  const stage = d.stage || '';
  const msg = d.message || '';
  const status = d.status || 'info';
  const icon = status==='running'?'⟳':status==='complete'?'✓':status==='error'?'✗':'·';
  const col = status==='complete'?'var(--green)':status==='error'?'var(--red)':
              status==='running'?'var(--blue)':'var(--muted)';
  el.innerHTML = `<span style="color:${col};margin-right:6px;">${icon}</span>
    <span style="color:var(--purple);margin-right:4px;">[${stage.toUpperCase()}]</span>
    <span>${msg}</span>`;
}

/* ── IaC display + download ── */
function showIaC(d) {
  const preview = document.getElementById('iac-preview');
  const filesDiv = document.getElementById('iac-files');
  preview.style.display = 'flex';
  preview.style.flexDirection = 'column';
  filesDiv.innerHTML = '';

  const tf = d.terraform_contents || {};
  const ans = d.ansible_contents || {};
  const tid = d.task_id || currentTaskId || '';

  const allFiles = [
    ...Object.entries(tf).map(([f, c]) => ({f, c, type:'terraform', icon:'🟦', color:'var(--blue)'})),
    ...Object.entries(ans).map(([f, c]) => ({f, c, type:'ansible', icon:'🟡', color:'var(--yellow)'})),
  ];

  if (allFiles.length === 0) {
    filesDiv.innerHTML = '<div class="empty">No IaC files generated</div>';
    return;
  }

  allFiles.forEach(({f, c, type, icon, color}) => {
    const div = document.createElement('div');
    div.className = 'iac-panel';
    const escaped = (c || '# (empty)').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    div.innerHTML = `
      <div class="iac-head">
        <span style="color:${color}">${icon}</span>
        <span class="iac-fname">${type}/${f}</span>
        <button class="download-btn" onclick="downloadFile('${tid}','${type}/${f}','${f}')">⬇ ${f}</button>
      </div>
      <div class="iac-body">${escaped}</div>`;
    filesDiv.appendChild(div);
  });

}

function downloadFile(taskId, path, filename) {
  // If we have contents in memory, download directly
  const parts = path.split('/');
  const section = parts[0];
  const fname = parts.slice(1).join('/');
  const content = iacContents[section] && iacContents[section][fname];
  if (content) {
    const blob = new Blob([content], {type:'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    return;
  }
  // Fallback: fetch from server
  window.open(`/api/iac/${taskId}/file?path=${encodeURIComponent(path)}`, '_blank');
}

function downloadAll() {
  const tid = iacContents.task_id || currentTaskId;
  if (!tid) return;
  // Check if we have contents in memory
  const tfCount = Object.keys(iacContents.terraform || {}).length;
  const ansCount = Object.keys(iacContents.ansible || {}).length;
  if (tfCount + ansCount === 0) return;
  // Build zip in browser using JSZip (if available) or fallback to server
  window.open(`/api/iac/${tid}`, '_blank');
}

/* ── HITL ── */
function renderHitl() {
  const pending = Object.values(pendingHitl).filter(h => h.status === 'pending');
  const panel = document.getElementById('hitl-panel');
  const container = document.getElementById('hitl-requests');
  if (!pending.length) { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  container.innerHTML = pending.map(h => `
    <div class="hitl-card">
      <div class="hitl-title">⚠️ HITL Request — Task ${(h.task_id||'').slice(0,8)}</div>
      <div class="hitl-info">
        <b>Reason:</b> ${h.reason || ''}<br>
        <b>Risk:</b> ${((h.aggregate_risk||0)*100).toFixed(0)}%<br>
        <b>Recommended:</b> ${h.recommended_action || ''}<br>
        <b>Patterns:</b> ${(h.flagged_patterns||[]).join(', ') || 'none'}
      </div>
      <div class="hitl-actions">
        <button class="btn btn-green btn-sm" onclick="resolveHitl('${h.hitl_request_id}','APPROVE')">✓ Approve</button>
        <button class="btn btn-red btn-sm" onclick="resolveHitl('${h.hitl_request_id}','REJECT')">✗ Reject</button>
      </div>
    </div>`).join('');
}

async function resolveHitl(reqId, decision) {
  const operator = prompt(`Operator ID (leave blank for "operator"):`) || 'operator';
  const notes = prompt(`Notes for ${decision}:`) || '';
  try {
    const r = await fetch(`/api/hitl/${reqId}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({decision, operator_id: operator, notes}),
    });
    const d = await r.json();
    if (d.error) { alert(d.error); return; }
    if (pendingHitl[reqId]) pendingHitl[reqId].status = 'resolved';
    renderHitl();
  } catch(e) { alert('Failed to submit HITL decision: ' + e); }
}

/* ── VM grid ── */
function renderVMs() {
  const grid = document.getElementById('vm-grid');
  const active = Object.values(vms);
  const running = active.filter(v => v.status === 'running');
  document.getElementById('vm-count').textContent = running.length;
  if (!active.length) {
    grid.innerHTML = '<div class="empty" style="grid-column:span 2;">No VMs</div>';
    return;
  }
  grid.innerHTML = active.map(v => {
    const col = ROLE_COLORS[v.role] || '#6c7086';
    const age = v.created_at ? Math.floor((Date.now()/1000) - v.created_at) : 0;
    return `<div class="vm-card ${v.status}">
      <div class="vm-role"><div class="vm-dot ${v.status}" style="background:${v.status==='running'?col:'var(--muted)'}"></div>${(v.role||'').replace(/_/g,' ')}</div>
      <div class="vm-id">${v.vm_id||''}</div>
      <div class="vm-ip">${v.private_ip||''}</div>
      <div style="font-size:9px;color:var(--muted)">${age}s</div>
    </div>`;
  }).join('');
}

/* ── Task list ── */
function renderTasks() {
  const el = document.getElementById('task-list');
  document.getElementById('task-count').textContent = tasks.length;
  if (!tasks.length) { el.innerHTML = '<div class="empty">No tasks yet</div>'; return; }
  el.innerHTML = tasks.slice(0,10).map(t => {
    const risk = t.aggregate_risk || 0;
    const rClass = risk>.7?'risk-crit':risk>.5?'risk-high':risk>.25?'risk-med':'risk-low';
    const dec = t.decision;
    const dClass = dec==='APPROVE'?'bg-green':dec==='REJECT'?'bg-red':
                   dec==='APPROVE_WITH_CONSTRAINTS'?'bg-yellow':
                   t.status==='running'?'bg-blue':'bg-muted';
    const repo = (t.repo_url||'').replace('https://github.com/','');
    return `<div class="task-card">
      <div class="task-top">
        <span class="task-id">${(t.task_id||'').slice(0,12)}</span>
        <span class="badge-small ${dClass}">${dec||t.status||'running'}</span>
      </div>
      <div class="task-repo">⎇ ${repo||'unknown'}</div>
      ${risk>0?`<div class="risk-bar ${rClass}" style="width:${(risk*100).toFixed(0)}%"></div>`:''}
    </div>`;
  }).join('');
}

/* ── Stats ── */
function renderStats() {
  document.getElementById('s-total').textContent = stats.total_tasks||0;
  document.getElementById('s-approved').textContent = stats.approved||0;
  document.getElementById('s-rejected').textContent = stats.rejected||0;
  document.getElementById('s-hitl').textContent = stats.hitl_escalated||0;
}

/* ── Log ── */
function renderLog() {
  const el = document.getElementById('log-panel');
  document.getElementById('log-count').textContent = logs.length;
  if (!logs.length) { el.innerHTML = '<div class="empty">No events</div>'; return; }
  el.innerHTML = logs.slice(0,100).map(ev => {
    const d = ev.data || {};
    const ts = new Date((ev.timestamp||0)*1000).toLocaleTimeString();
    const sev = ev.severity || 'info';
    const msg = d.message || ev.type || '';
    const stage = d.stage || '';
    const sevClass = sev==='error'?'sev-error':sev==='success'?'sev-success':sev==='warning'?'sev-warning':'sev-info';
    return `<div class="log-entry">
      <span class="log-time">${ts}</span>
      <span class="log-sev ${sevClass}">${sev.slice(0,4).toUpperCase()}</span>
      <span class="log-msg">
        ${d.task_id?`<span class="task-tag">${d.task_id.slice(0,8)}</span>`:''}
        ${stage?`<span class="stage-tag">[${stage}]</span>`:''}
        ${msg}
      </span>
    </div>`;
  }).join('');
}

function renderAll() {
  renderStats(); renderTasks(); renderVMs(); renderLog(); renderHitl();
}



/* ── Resource Map ── */
const ROLE_ICONS = {
  secure_fetcher:  '🌐', ast_parser:     '🌳', ir_builder:    '⚙️',
  ml_analyzer:     '🤖', policy_engine:  '⚖️', strategy_agent:'🗺️',
  iac_generator:   '📄', deployment_agent:'🚀', feasibility_validator:'🔍',
};

function mapSetStatus(txt) {
  const el = document.getElementById('res-map-status');
  if (el) el.textContent = txt;
}

function mapBootstrap(vnetName, nsgName) {
  const map = document.getElementById('res-map');
  if (map) map.classList.remove('destroyed');
  const banner = document.querySelector('.res-map-destroyed-banner');
  if (banner) banner.style.display = 'none';

  const vn = document.getElementById('vnet-name');
  if (vn) vn.textContent = vnetName || '—';

  const rn = document.getElementById('rg-name');
  if (rn) rn.textContent = 'rg-secure-analysis';

  const nsgBadge = document.getElementById('nsg-badge');
  const nsgName2 = document.getElementById('nsg-name');
  if (nsgBadge) nsgBadge.className = 'nsg-badge active';
  if (nsgName2) nsgName2.textContent = nsgName || 'NSG';

  // Show KV badge if vault name known
  const vault = 'kv-secanalysis';
  const kvBadge = document.getElementById('kv-badge');
  const kvName  = document.getElementById('kv-name');
  if (kvBadge) kvBadge.style.display = 'flex';
  if (kvName)  kvName.textContent = vault;

  // Clear placeholder
  const nodes = document.getElementById('res-nodes');
  if (nodes) nodes.innerHTML = '';

  mapSetStatus('🟢 active');
}

function mapAddNode(vmId, role, azureName, ip) {
  const nodes = document.getElementById('res-nodes');
  if (!nodes) return;

  // Remove placeholder if present
  const placeholder = nodes.querySelector('[data-placeholder]');
  if (placeholder) placeholder.remove();

  const col = ROLE_COLORS[role] || '#89b4fa';
  const icon = ROLE_ICONS[role] || '📦';
  const label = (role || '').replace(/_/g, '-');
  const shortName = (azureName || vmId || '').slice(0, 18);
  const tip = `${role} · ${ip || ''} · ${shortName}`;

  const el = document.createElement('div');
  el.className = 'res-node spawning running';
  el.id = `resnode-${vmId}`;
  el.dataset.tip = tip;
  el.style.borderColor = col;
  el.style.color = col;
  el.style.background = `${col}0d`;
  el.innerHTML = `
    <div class="res-dot" style="background:${col}"></div>
    <span>${icon}</span>
    <span class="res-name">${label}</span>
  `;
  nodes.appendChild(el);
}

function mapTerminateNode(vmId, reason) {
  const el = document.getElementById(`resnode-${vmId}`);
  if (!el) return;
  el.classList.remove('running', 'spawning');
  el.classList.add('terminated');
  const dot = el.querySelector('.res-dot');
  if (dot) dot.style.background = 'var(--muted)';
  // Update tooltip
  el.dataset.tip = (el.dataset.tip || '') + ` · ${reason || 'terminated'}`;
  // Fade out after 4 seconds
  setTimeout(() => {
    el.style.transition = 'opacity 1.2s ease';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 1300);
  }, 4000);
}

function mapTeardown() {
  const map = document.getElementById('res-map');
  if (map) map.classList.add('destroyed');
  mapSetStatus('🔴 destroyed');
  // Terminate all remaining nodes
  document.querySelectorAll('.res-node.running').forEach(el => {
    el.classList.remove('running');
    el.classList.add('terminated');
  });
}



/* ── Analyze trigger ── */
async function analyze() {
  const url = document.getElementById('repo-url').value.trim();
  if (!url) return;
  resetPipeline();
  vms = {};
  try {
    const r = await fetch('/api/analyze', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({repo_url: url}),
    });
    const d = await r.json();
    if (d.error) { alert(d.error); return; }
    document.getElementById('repo-url').value = '';
    stats.total_tasks = (stats.total_tasks||0) + 1;
    renderStats();
  } catch(e) { alert('Failed to start analysis: ' + e); }
}

document.getElementById('repo-url').addEventListener('keydown', e => {
  if (e.key === 'Enter') analyze();
});

setInterval(renderVMs, 1000);
connect();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return DASHBOARD_HTML