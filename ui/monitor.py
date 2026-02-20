"""
Monitoring Dashboard

FastAPI app serving:
  GET  /           → interactive HTML dashboard
  GET  /api/tasks  → recent tasks
  GET  /api/logs   → audit log entries
  GET  /api/stats  → platform stats
  POST /api/analyze → trigger analysis
  WS   /ws         → real-time event stream
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)

app = FastAPI(title="Secure Analysis Platform", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

MAX_EVENTS = 1000
_events: Deque[Dict] = deque(maxlen=MAX_EVENTS)
_active_tasks: Dict[str, Dict] = {}
_ws_clients: List[WebSocket] = []
_stats = {"total_tasks": 0, "approved": 0, "rejected": 0,
          "hitl_escalated": 0, "start_time": time.time()}


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

/* Header */
.hdr{background:var(--surface);border-bottom:1px solid var(--border);padding:10px 20px;
     display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100;}
.hdr-logo{display:flex;align-items:center;gap:8px;}
.hdr-logo svg{flex-shrink:0;}
.hdr-title{font-weight:700;font-size:15px;letter-spacing:-.3px;}
.hdr-sub{font-size:11px;color:var(--muted);}
.ws-badge{margin-left:auto;font-size:11px;padding:3px 8px;border-radius:99px;
          border:1px solid currentColor;font-family:'IBM Plex Mono',monospace;}
.ws-connected{color:var(--green);}
.ws-disconnected{color:var(--red);}

/* Layout */
.layout{display:grid;grid-template-columns:340px 1fr 300px;grid-template-rows:auto 1fr;
        gap:1px;background:var(--border);height:calc(100vh - 45px);}
.panel{background:var(--bg);display:flex;flex-direction:column;overflow:hidden;}
.panel-hdr{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;
           align-items:center;gap:8px;font-size:11px;font-weight:600;letter-spacing:.8px;
           text-transform:uppercase;color:var(--muted);flex-shrink:0;}
.panel-hdr .badge{margin-left:auto;background:var(--surface2);padding:2px 7px;
                  border-radius:99px;font-size:10px;color:var(--text);}
.panel-body{flex:1;overflow-y:auto;padding:12px;}
.panel-body::-webkit-scrollbar{width:4px;}
.panel-body::-webkit-scrollbar-track{background:transparent;}
.panel-body::-webkit-scrollbar-thumb{background:var(--subtle);border-radius:2px;}

/* Input bar */
.input-bar{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px;flex-shrink:0;}
.input-bar input{flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--text);
                 padding:7px 12px;border-radius:6px;font-size:12px;font-family:inherit;outline:none;}
.input-bar input:focus{border-color:var(--blue);}
.input-bar input::placeholder{color:var(--muted);}
.btn{padding:7px 14px;border-radius:6px;border:none;cursor:pointer;font-size:12px;
     font-family:inherit;font-weight:600;transition:.15s;}
.btn-blue{background:var(--blue);color:#000;}
.btn-blue:hover{opacity:.85;}

/* Stats row */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px;}
.stat-box{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 12px;}
.stat-val{font-size:22px;font-weight:700;font-family:'IBM Plex Mono',monospace;margin-bottom:2px;}
.stat-lbl{font-size:10px;color:var(--muted);letter-spacing:.5px;text-transform:uppercase;}
.stat-green{color:var(--green);}
.stat-red{color:var(--red);}
.stat-blue{color:var(--blue);}
.stat-yellow{color:var(--yellow);}

/* Pipeline viz */
.pipeline{display:flex;align-items:center;gap:0;overflow-x:auto;padding:4px 0 8px;margin-bottom:12px;}
.pip-stage{flex:1;min-width:78px;text-align:center;position:relative;}
.pip-stage:not(:last-child)::after{content:'';position:absolute;right:-1px;top:50%;
  transform:translateY(-50%);width:2px;height:60%;background:var(--border);z-index:1;}
.pip-icon{width:36px;height:36px;border-radius:8px;margin:0 auto 4px;display:flex;
          align-items:center;justify-content:center;font-size:16px;
          border:1px solid var(--border);background:var(--surface);transition:.3s;}
.pip-name{font-size:9px;color:var(--muted);letter-spacing:.3px;text-transform:uppercase;line-height:1.2;}
.pip-stage.running .pip-icon{animation:pip-pulse 1s ease-in-out infinite;border-color:var(--blue);}
.pip-stage.complete .pip-icon{background:var(--green-dim);border-color:var(--green);}
.pip-stage.error .pip-icon{background:var(--red-dim);border-color:var(--red);}
@keyframes pip-pulse{0%,100%{box-shadow:0 0 0 0 rgba(137,180,250,.4);}50%{box-shadow:0 0 0 6px rgba(137,180,250,0);}}

/* Task cards */
.task-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
           padding:12px;margin-bottom:8px;transition:.2s;}
.task-card:hover{border-color:var(--subtle);}
.task-top{display:flex;align-items:center;gap:8px;margin-bottom:6px;}
.task-id{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);}
.task-repo{font-size:11px;color:var(--blue);overflow:hidden;text-overflow:ellipsis;
           white-space:nowrap;margin-bottom:6px;}
.risk-bar{height:3px;background:var(--surface2);border-radius:2px;margin:6px 0 4px;}
.risk-fill{height:100%;border-radius:2px;transition:width .5s;}
.risk-low{background:var(--green);}
.risk-med{background:var(--yellow);}
.risk-high{background:var(--orange);}
.risk-crit{background:var(--red);}
.task-meta{display:flex;gap:10px;font-size:10px;color:var(--muted);flex-wrap:wrap;}
.task-meta span{display:flex;align-items:center;gap:3px;}
.badge-small{font-size:10px;padding:2px 7px;border-radius:99px;font-weight:600;}
.bg-green{background:var(--green-dim);color:var(--green);}
.bg-red{background:var(--red-dim);color:var(--red);}
.bg-yellow{background:var(--yellow-dim);color:var(--yellow);}
.bg-blue{background:var(--blue-dim);color:var(--blue);}
.bg-muted{background:var(--surface2);color:var(--muted);}

/* VM grid */
.vm-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;}
.vm-card{background:var(--surface);border:1px solid var(--border);border-radius:6px;
         padding:8px 10px;transition:.3s;}
.vm-card.running{border-color:var(--subtle);}
.vm-card.terminated{opacity:.45;}
.vm-role{font-size:10px;font-weight:600;letter-spacing:.3px;text-transform:uppercase;
         margin-bottom:3px;display:flex;align-items:center;gap:5px;}
.vm-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;}
.vm-dot.running{background:var(--green);animation:blink 1.5s ease infinite;}
.vm-dot.terminated{background:var(--muted);}
.vm-dot.provisioning{background:var(--blue);animation:blink 1s ease infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.vm-id{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);}
.vm-ip{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--teal);}
.vm-age{font-size:9px;color:var(--muted);}

/* Log */
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

/* IaC preview */
.iac-panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;
           margin-bottom:8px;overflow:hidden;}
.iac-head{padding:8px 12px;background:var(--surface2);border-bottom:1px solid var(--border);
          display:flex;align-items:center;gap:8px;font-size:11px;font-weight:600;}
.iac-body{padding:10px 12px;font-family:'IBM Plex Mono',monospace;font-size:10px;
          color:var(--muted);max-height:120px;overflow-y:auto;line-height:1.6;}
.iac-kw{color:var(--purple);}
.iac-str{color:var(--green);}
.iac-comment{color:var(--muted);}

/* Empty states */
.empty{text-align:center;color:var(--muted);padding:24px;font-size:12px;}

/* Azure topology */
.topology{position:relative;height:180px;background:var(--surface);border:1px solid var(--border);
          border-radius:8px;margin-bottom:12px;overflow:hidden;}
.topo-label{position:absolute;font-size:9px;color:var(--muted);letter-spacing:.5px;text-transform:uppercase;}
.topo-box{position:absolute;border:1px solid;border-radius:6px;padding:4px 8px;font-size:9px;
          font-weight:600;text-align:center;transition:.5s;}
.topo-rg{top:10px;left:10px;right:10px;bottom:10px;border-color:var(--border);border-radius:10px;
         background:transparent;pointer-events:none;}
.topo-vnet{top:30px;left:20px;width:200px;height:120px;border-color:var(--blue-dim);
           background:rgba(137,180,250,.04);}
.topo-subnet{top:55px;left:30px;width:180px;height:70px;border-color:var(--subtle);
             background:rgba(137,180,250,.02);}
.topo-nsg{top:30px;right:20px;width:100px;border-color:var(--orange);
          background:rgba(250,179,135,.06);color:var(--orange);}
.topo-aci{top:60px;right:30px;width:80px;border-color:var(--teal);
          background:rgba(148,226,213,.06);color:var(--teal);}
.topo-agent{border-color:var(--blue);background:rgba(137,180,250,.08);color:var(--blue);}
.topo-agent.active{border-color:var(--blue);box-shadow:0 0 8px rgba(137,180,250,.3);}

/* Scrollbar for small panels */
.scrollable{overflow-y:auto;max-height:100%;}
.scrollable::-webkit-scrollbar{width:3px;}
.scrollable::-webkit-scrollbar-thumb{background:var(--subtle);}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-logo">
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
      <path d="M14 2L3 8v8c0 6.08 4.7 11.74 11 12.94C20.3 27.74 25 22.08 25 16V8L14 2z"
            fill="rgba(137,180,250,.12)" stroke="#89b4fa" stroke-width="1.5"/>
      <path d="M9.5 14l3.5 3.5 6.5-6.5" stroke="#a6e3a1" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div>
      <div class="hdr-title">Secure Analysis Platform</div>
      <div class="hdr-sub">Zero-trust · mTLS · AES-256 · Ephemeral µVMs</div>
    </div>
  </div>
  <div id="ws-status" class="ws-badge ws-disconnected">● disconnected</div>
</div>

<div class="layout">

  <!-- LEFT: Input + Tasks -->
  <div class="panel">
    <div class="input-bar">
      <input id="repo-url" type="text"
             placeholder="https://github.com/owner/repo"
             autocomplete="off"/>
      <button class="btn btn-blue" onclick="analyze()">Analyze</button>
    </div>

    <div class="panel-hdr">
      📊 Stats
    </div>
    <div style="padding:10px 12px;flex-shrink:0;">
      <div class="stats-row">
        <div class="stat-box">
          <div class="stat-val stat-blue" id="s-total">0</div>
          <div class="stat-lbl">Total</div>
        </div>
        <div class="stat-box">
          <div class="stat-val stat-green" id="s-approved">0</div>
          <div class="stat-lbl">Approved</div>
        </div>
        <div class="stat-box">
          <div class="stat-val stat-red" id="s-rejected">0</div>
          <div class="stat-lbl">Rejected</div>
        </div>
        <div class="stat-box">
          <div class="stat-val stat-yellow" id="s-hitl">0</div>
          <div class="stat-lbl">HITL</div>
        </div>
      </div>
    </div>

    <div class="panel-hdr">🔁 Pipeline <span class="badge" id="task-count">0</span></div>
    <div class="panel-body" id="task-list">
      <div class="empty">Enter a GitHub URL to start analysis</div>
    </div>
  </div>

  <!-- CENTER: Azure topology + pipeline stages + IaC preview -->
  <div class="panel">
    <div class="panel-hdr">🌐 Azure Environment</div>
    <div class="panel-body">

      <!-- Azure topology diagram -->
      <div class="topology" id="topology">
        <div class="topo-box topo-rg"></div>
        <div class="topo-label" style="top:12px;left:16px;">Resource Group</div>
        <div class="topo-box topo-vnet">
          <div style="font-size:8px;color:var(--blue);margin-bottom:2px;">VNet 10.0.0.0/16</div>
          <div class="topo-box topo-subnet" style="position:relative;left:0;top:0;width:auto;height:auto;margin:2px 0;">
            <span style="color:var(--sky)">Subnet 10.0.1.0/24</span>
            <div id="topo-agents" style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px;justify-content:center;"></div>
          </div>
        </div>
        <div class="topo-box topo-nsg" id="topo-nsg">NSG<br><span style="font-size:8px;font-weight:400;color:var(--muted)">DenyAll</span></div>
        <div class="topo-box topo-aci" id="topo-aci" style="display:none;">ACI<br><span style="font-size:8px">sandbox</span></div>
      </div>

      <!-- Pipeline stages -->
      <div class="pipeline" id="pipeline-viz">
        <div class="pip-stage" id="pip-fetch" data-role="secure_fetcher">
          <div class="pip-icon">🌐</div>
          <div class="pip-name">Fetch</div>
        </div>
        <div class="pip-stage" id="pip-parse" data-role="ast_parser">
          <div class="pip-icon">🌳</div>
          <div class="pip-name">Parse</div>
        </div>
        <div class="pip-stage" id="pip-ir" data-role="ir_builder">
          <div class="pip-icon">⚙️</div>
          <div class="pip-name">IR Build</div>
        </div>
        <div class="pip-stage" id="pip-ml" data-role="ml_analyzer">
          <div class="pip-icon">🤖</div>
          <div class="pip-name">ML Score</div>
        </div>
        <div class="pip-stage" id="pip-policy" data-role="policy_engine">
          <div class="pip-icon">⚖️</div>
          <div class="pip-name">Policy</div>
        </div>
        <div class="pip-stage" id="pip-strategy" data-role="strategy_agent">
          <div class="pip-icon">🗺️</div>
          <div class="pip-name">Strategy</div>
        </div>
        <div class="pip-stage" id="pip-iac" data-role="iac_generator">
          <div class="pip-icon">📄</div>
          <div class="pip-name">IaC Gen</div>
        </div>
        <div class="pip-stage" id="pip-deploy" data-role="deployment_agent">
          <div class="pip-icon">🚀</div>
          <div class="pip-name">Deploy</div>
        </div>
      </div>

      <!-- Current stage detail -->
      <div id="stage-detail" style="background:var(--surface);border:1px solid var(--border);
           border-radius:8px;padding:10px 14px;margin-bottom:12px;min-height:44px;
           font-size:12px;color:var(--muted);">
        Awaiting analysis...
      </div>

      <!-- IaC preview (appears after stage 7) -->
      <div id="iac-preview" style="display:none;">
        <div class="panel-hdr" style="padding:8px 0;border:none;">📋 Generated IaC</div>
        <div id="iac-files"></div>
      </div>

    </div>
  </div>

  <!-- RIGHT: VMs + Audit Log -->
  <div class="panel">
    <div class="panel-hdr">
      💻 µVMs <span class="badge" id="vm-count">0</span>
    </div>
    <div style="padding:10px;flex-shrink:0;border-bottom:1px solid var(--border);">
      <div class="vm-grid" id="vm-grid">
        <div class="empty" style="grid-column:span 2;">No active VMs</div>
      </div>
    </div>

    <div class="panel-hdr">
      📋 Audit Log <span class="badge" id="log-count">0</span>
    </div>
    <div class="panel-body" id="log-panel"></div>
  </div>

</div>

<script>
let ws = null;
let stats = {total_tasks:0, approved:0, rejected:0, hitl_escalated:0};
let tasks = [];
let vms = {};        // vm_id → record
let logs = [];
let currentTask = null;
let pipelineState = {};  // stage → status

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

/* ── Event handler ── */
function handle(msg) {
  if (msg.type === 'init') {
    stats = msg.data.stats || stats;
    (msg.data.tasks || []).forEach(t => { tasks.unshift(t); currentTask = t; });
    (msg.data.events || []).forEach(e => processEvent(e, false));
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
      pipelineState = {};
      resetPipeline();
      break;

    case 'stage_update': {
      const stage = d.stage;
      if (STAGE_MAP[stage]) {
        pipelineState[stage] = d.status;
        setStage(STAGE_MAP[stage], d.status);
      }
      setDetail(d);
      if (stage === 'iac' && d.status === 'complete') showIaC(d);
      if (d.status === 'complete' && STAGE_MAP[stage]) {
        // auto-set next to running visually if still in pipeline
        const stages = Object.keys(STAGE_MAP);
        const idx = stages.indexOf(stage);
        if (idx >= 0 && idx < stages.length - 1) {
          const next = stages[idx + 1];
          // will be set by next stage_update
        }
      }
      if (currentTask) currentTask.last_stage = stage;
      break;
    }

    case 'vm_created':
      vms[d.vm_id] = {...d, status:'running', created_at: ev.timestamp || Date.now()/1000};
      break;

    case 'vm_terminated':
      if (vms[d.vm_id]) vms[d.vm_id].status = 'terminated';
      break;

    case 'environment_teardown':
      // mark all VMs terminated
      Object.values(vms).forEach(v => v.status = 'terminated');
      setDetail({message:'🧹 Ephemeral environment destroyed — VMs deleted. Audit log preserved.', stage:'teardown', status:'complete'});
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
  document.getElementById('stage-detail').textContent = 'Starting analysis...';
  document.getElementById('topo-aci').style.display = 'none';
  document.getElementById('topo-agents').innerHTML = '';
}

function setStage(pipId, status) {
  const el = document.getElementById(pipId);
  if (!el) return;
  el.className = 'pip-stage ' + (status === 'running' ? 'running' :
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
  const icon = status === 'running' ? '⟳' : status === 'complete' ? '✓' : status === 'error' ? '✗' : '·';
  const col = status === 'complete' ? 'var(--green)' : status === 'error' ? 'var(--red)' :
              status === 'running' ? 'var(--blue)' : 'var(--muted)';
  el.innerHTML = `<span style="color:${col};margin-right:6px;">${icon}</span>
    <span style="color:var(--purple);margin-right:4px;">[${stage.toUpperCase()}]</span>
    <span>${msg}</span>`;
}

function showIaC(d) {
  const preview = document.getElementById('iac-preview');
  const files = document.getElementById('iac-files');
  preview.style.display = 'block';
  const tfFiles = d.terraform_files || [];
  const ansFiles = d.ansible_files || [];
  files.innerHTML = '';
  [...tfFiles.map(f=>({f,type:'tf'})), ...ansFiles.map(f=>({f,type:'yml'}))].forEach(({f,type}) => {
    const icon = type === 'tf' ? '🟣' : '🟡';
    const div = document.createElement('div');
    div.className = 'iac-panel';
    div.innerHTML = `<div class="iac-head">${icon} ${f}</div>
      <div class="iac-body"><span class="iac-comment"># Generated Terraform/Ansible — mTLS enforced, NSG applied</span></div>`;
    files.appendChild(div);
  });
  document.getElementById('topo-aci').style.display = 'block';
}

/* ── VM grid ── */
function renderVMs() {
  const grid = document.getElementById('vm-grid');
  const agents = document.getElementById('topo-agents');
  const active = Object.values(vms);
  const running = active.filter(v => v.status === 'running');

  document.getElementById('vm-count').textContent = running.length;

  if (!active.length) {
    grid.innerHTML = '<div class="empty" style="grid-column:span 2;">No VMs</div>';
    agents.innerHTML = '';
    return;
  }

  grid.innerHTML = active.map(v => {
    const col = ROLE_COLORS[v.role] || '#6c7086';
    const age = v.created_at ? Math.floor((Date.now()/1000) - v.created_at) : 0;
    return `<div class="vm-card ${v.status}">
      <div class="vm-role">
        <div class="vm-dot ${v.status}" style="background:${v.status==='running'?col:'var(--muted)'}"></div>
        ${(v.role||'').replace(/_/g,' ')}
      </div>
      <div class="vm-id">${v.vm_id||''}</div>
      <div class="vm-ip">${v.private_ip||''}</div>
      <div class="vm-age">${age}s</div>
    </div>`;
  }).join('');

  // Update topology
  agents.innerHTML = running.map(v => {
    const col = ROLE_COLORS[v.role] || '#89b4fa';
    return `<div style="background:rgba(137,180,250,.06);border:1px solid ${col};
      border-radius:4px;padding:2px 5px;font-size:8px;color:${col};">
      ${(v.role||'').replace(/_/g,'_').slice(0,10)}</div>`;
  }).join('');
}

/* ── Task list ── */
function renderTasks() {
  const el = document.getElementById('task-list');
  document.getElementById('task-count').textContent = tasks.length;
  if (!tasks.length) {
    el.innerHTML = '<div class="empty">No tasks yet</div>'; return;
  }
  el.innerHTML = tasks.slice(0,10).map(t => {
    const risk = t.aggregate_risk || 0;
    const rClass = risk > .7 ? 'risk-crit' : risk > .5 ? 'risk-high' :
                   risk > .25 ? 'risk-med' : 'risk-low';
    const dec = t.decision;
    const dClass = dec === 'APPROVE' ? 'bg-green' : dec === 'REJECT' ? 'bg-red' :
                   dec === 'APPROVE_WITH_CONSTRAINTS' ? 'bg-yellow' :
                   t.status === 'running' ? 'bg-blue' : 'bg-muted';
    const dText = dec || t.status || 'running';
    const repo = (t.repo_url||'').replace('https://github.com/','');
    const method = t.deployment_method;
    return `<div class="task-card">
      <div class="task-top">
        <span class="task-id">${(t.task_id||'').slice(0,12)}</span>
        <span class="badge-small ${dClass}">${dText}</span>
      </div>
      <div class="task-repo">⎇ ${repo||'unknown'}</div>
      ${risk > 0 ? `<div class="risk-bar"><div class="risk-fill ${rClass}"
        style="width:${(risk*100).toFixed(0)}%"></div></div>` : ''}
      <div class="task-meta">
        <span>🎯 ${(risk*100).toFixed(0)}%</span>
        <span>📁 ${t.total_files||0} files</span>
        ${t.high_risk_files ? `<span style="color:var(--red)">⚠ ${t.high_risk_files} high-risk</span>`:''}
        ${method ? `<span style="color:var(--teal)">⚙ ${method}</span>`:''}
        ${t.hitl_required ? `<span style="color:var(--yellow)">👤 HITL</span>`:''}
        ${t.duration_seconds ? `<span>${t.duration_seconds.toFixed(1)}s</span>`:''}
      </div>
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
  if (!logs.length) { el.innerHTML = '<div class="empty">No events yet</div>'; return; }
  el.innerHTML = logs.slice(0,150).map(ev => {
    const t = new Date((ev.timestamp||Date.now()/1000)*1000);
    const ts = t.toTimeString().slice(0,8);
    const sev = ev.severity || 'info';
    const d = ev.data || {};
    const stage = d.stage || ev.type.replace(/_/g,' ');
    const msg = d.message || ev.type;
    const sevClass = sev==='success'?'sev-success':sev==='error'?'sev-error':
                     sev==='warning'?'sev-warning':'sev-info';
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
  renderStats(); renderTasks(); renderVMs(); renderLog();
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

setInterval(renderVMs, 1000);  // refresh VM ages
connect();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return DASHBOARD_HTML