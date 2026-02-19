"""
Monitoring Dashboard

Real-time monitoring UI for the secure analysis platform.
Features:
  - Live task status updates via WebSocket
  - VM lifecycle visualization
  - Risk scores and policy decisions
  - Security event log
  - Agent health status

Security note: This dashboard displays ONLY structured metadata.
No code, no IR, no AST data is ever shown.
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

app = FastAPI(title="Secure Analysis Platform Monitor", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory event store (no persistence)
MAX_EVENTS = 500
_events: Deque[Dict] = deque(maxlen=MAX_EVENTS)
_active_tasks: Dict[str, Dict] = {}
_active_vms: Dict[str, Dict] = {}
_websocket_clients: List[WebSocket] = []
_stats = {
    "total_tasks": 0,
    "approved": 0,
    "rejected": 0,
    "hitl_escalated": 0,
    "vms_created": 0,
    "vms_destroyed": 0,
    "start_time": time.time(),
}


async def broadcast(event: Dict) -> None:
    """Broadcast event to all connected WebSocket clients."""
    event["timestamp"] = time.time()
    _events.appendleft(event)
    disconnected = []
    for ws in _websocket_clients:
        try:
            await ws.send_json(event)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        _websocket_clients.remove(ws)


def add_event(event_type: str, data: Dict, severity: str = "info") -> None:
    """Add event (thread-safe wrapper for sync code)."""
    event = {"type": event_type, "severity": severity, "data": data}
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(broadcast(event))
        else:
            _events.appendleft({**event, "timestamp": time.time()})
    except RuntimeError:
        _events.appendleft({**event, "timestamp": time.time()})


# ─────────────────────────── REST API ───────────────────────────


@app.get("/api/events")
async def get_events(limit: int = 100) -> List[Dict]:
    """Get recent events."""
    return list(_events)[:limit]


@app.get("/api/tasks")
async def get_tasks() -> Dict:
    """Get active and recent tasks."""
    return {
        "active": list(_active_tasks.values()),
        "stats": _stats,
    }


@app.get("/api/vms")
async def get_vms() -> List[Dict]:
    """Get active VM inventory."""
    try:
        from src.azure_setup import MicroVMOrchestrator
        # Would return real VM data from orchestrator
        return list(_active_vms.values())
    except Exception:
        return list(_active_vms.values())


@app.get("/api/health")
async def health() -> Dict:
    """Platform health check."""
    return {
        "status": "healthy",
        "uptime_seconds": time.time() - _stats["start_time"],
        "active_tasks": len(_active_tasks),
        "active_vms": len(_active_vms),
        "total_events": len(_events),
    }


@app.post("/api/analyze")
async def trigger_analysis(request: Dict[str, Any]) -> Dict:
    """Trigger repository analysis."""
    repo_url = request.get("repo_url", "")
    if not repo_url:
        return {"error": "repo_url required"}

    import secrets
    task_id = secrets.token_hex(8)
    _active_tasks[task_id] = {
        "task_id": task_id,
        "repo_url": repo_url,
        "status": "running",
        "started_at": time.time(),
    }
    _stats["total_tasks"] += 1

    add_event("task_started", {"task_id": task_id, "repo_url": repo_url})

    # Run analysis in background
    asyncio.create_task(_run_analysis_task(task_id, repo_url))

    return {"task_id": task_id, "status": "started"}


async def _run_analysis_task(task_id: str, repo_url: str) -> None:
    """Background analysis task with event broadcasting."""
    try:
        from src.main import get_pipeline
        pipeline = get_pipeline()

        add_event("stage_update", {
            "task_id": task_id, "stage": "fetch", "status": "running"
        })

        result = await pipeline.run_analysis(repo_url, task_id)

        # Update stats
        decision = result.get("decision", "UNKNOWN")
        if decision == "APPROVE":
            _stats["approved"] += 1
        elif decision == "REJECT":
            _stats["rejected"] += 1

        _active_tasks[task_id] = {**_active_tasks.get(task_id, {}), **result}

        severity = "error" if decision == "REJECT" else "warning" if result.get("hitl_required") else "success"
        add_event("task_complete", result, severity=severity)

    except Exception as e:
        logger.error("Analysis task %s failed: %s", task_id, e)
        _active_tasks[task_id] = {
            **_active_tasks.get(task_id, {}),
            "status": "failed",
            "error": type(e).__name__,
        }
        add_event("task_failed", {"task_id": task_id, "error": type(e).__name__}, severity="error")


# ─────────────────────────── WebSocket ───────────────────────────


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """Real-time event stream via WebSocket."""
    await ws.accept()
    _websocket_clients.append(ws)
    try:
        # Send current state on connect
        await ws.send_json({
            "type": "init",
            "data": {
                "events": list(_events)[:50],
                "stats": _stats,
                "active_tasks": list(_active_tasks.values()),
                "active_vms": list(_active_vms.values()),
            },
            "timestamp": time.time(),
        })
        # Keep connection alive
        while True:
            msg = await asyncio.wait_for(ws.receive_text(), timeout=30)
            if msg == "ping":
                await ws.send_json({"type": "pong", "timestamp": time.time()})
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        if ws in _websocket_clients:
            _websocket_clients.remove(ws)


# ─────────────────────────── HTML UI ───────────────────────────


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Analysis Platform — Monitor</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
      --border: #30363d; --text: #e6edf3; --muted: #8b949e;
      --green: #3fb950; --red: #f85149; --yellow: #d29922;
      --blue: #388bfd; --purple: #bc8cff; --orange: #d2844f;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; font-size: 14px; }
    
    header {
      background: var(--surface); border-bottom: 1px solid var(--border);
      padding: 12px 24px; display: flex; align-items: center; gap: 16px;
    }
    header h1 { font-size: 16px; font-weight: 600; }
    .badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
    .badge-green { background: #1c3025; color: var(--green); }
    .badge-red { background: #3d1c1c; color: var(--red); }
    .badge-yellow { background: #3d2e0e; color: var(--yellow); }
    .badge-blue { background: #0d2444; color: var(--blue); }
    #conn-status { margin-left: auto; }
    
    main { display: grid; grid-template-columns: 1fr 1fr; grid-template-rows: auto 1fr; gap: 16px; padding: 16px; height: calc(100vh - 57px); }
    
    .panel {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; overflow: hidden; display: flex; flex-direction: column;
    }
    .panel-header {
      padding: 12px 16px; border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px;
    }
    .panel-body { padding: 16px; overflow-y: auto; flex: 1; }
    
    /* Stats Row */
    .stats-row { grid-column: 1 / -1; }
    .stats-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; }
    .stat-card {
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 6px; padding: 12px 16px;
    }
    .stat-value { font-size: 28px; font-weight: 700; line-height: 1; }
    .stat-label { color: var(--muted); font-size: 11px; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    
    /* Analyze Form */
    .analyze-form { display: flex; gap: 8px; margin-bottom: 16px; }
    .analyze-form input {
      flex: 1; background: var(--surface2); border: 1px solid var(--border);
      color: var(--text); padding: 8px 12px; border-radius: 6px; font-size: 13px;
    }
    .analyze-form input:focus { outline: 1px solid var(--blue); }
    .btn {
      background: var(--blue); color: white; border: none; padding: 8px 16px;
      border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;
    }
    .btn:hover { opacity: 0.85; }
    
    /* Tasks */
    .task-item {
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 6px; padding: 12px; margin-bottom: 8px;
    }
    .task-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .task-id { font-family: monospace; font-size: 11px; color: var(--muted); }
    .risk-bar { height: 4px; background: var(--border); border-radius: 2px; margin: 6px 0; overflow: hidden; }
    .risk-fill { height: 100%; border-radius: 2px; transition: width 0.5s; }
    .risk-0 { background: var(--green); }
    .risk-1 { background: var(--yellow); }
    .risk-2 { background: var(--orange); }
    .risk-3 { background: var(--red); }
    .task-meta { display: flex; gap: 12px; font-size: 11px; color: var(--muted); }
    
    /* Event Log */
    .event-log { font-family: monospace; font-size: 12px; }
    .event-item {
      padding: 6px 0; border-bottom: 1px solid var(--border);
      display: grid; grid-template-columns: 80px 120px 1fr; gap: 8px;
    }
    .event-time { color: var(--muted); }
    .event-type { }
    .event-type.info { color: var(--blue); }
    .event-type.success { color: var(--green); }
    .event-type.warning { color: var(--yellow); }
    .event-type.error { color: var(--red); }
    .event-data { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    
    /* VM Grid */
    .vm-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 8px; }
    .vm-card {
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 6px; padding: 10px; font-size: 11px;
    }
    .vm-card.running { border-color: var(--green); }
    .vm-card.terminating { border-color: var(--yellow); opacity: 0.7; }
    .vm-card.terminated { border-color: var(--border); opacity: 0.4; }
    .vm-role { font-weight: 600; font-size: 12px; margin-bottom: 4px; }
    .vm-id { color: var(--muted); }
    .vm-age { color: var(--muted); margin-top: 4px; }
    .vm-status-dot {
      display: inline-block; width: 6px; height: 6px; border-radius: 50%;
      margin-right: 4px;
    }
    .dot-running { background: var(--green); animation: pulse 2s infinite; }
    .dot-terminating { background: var(--yellow); }
    .dot-terminated { background: var(--muted); }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
    
    .empty-state { color: var(--muted); text-align: center; padding: 24px; font-size: 13px; }
  </style>
</head>
<body>
  <header>
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M10 1L2 5v5c0 4.4 3.4 8.5 8 9.5 4.6-1 8-5.1 8-9.5V5L10 1z" fill="#388bfd" opacity="0.2" stroke="#388bfd" stroke-width="1.5"/>
      <path d="M7 10l2 2 4-4" stroke="#3fb950" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <h1>Secure Analysis Platform</h1>
    <span class="badge badge-blue">Zero Trust</span>
    <span class="badge badge-green">mTLS</span>
    <span class="badge badge-blue">Ephemeral VMs</span>
    <span id="conn-status" class="badge badge-yellow">Connecting...</span>
  </header>
  
  <main>
    <!-- Stats Row -->
    <div class="panel stats-row">
      <div class="panel-body">
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-value" id="stat-total">0</div>
            <div class="stat-label">Total Tasks</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="color:var(--green)" id="stat-approved">0</div>
            <div class="stat-label">Approved</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="color:var(--red)" id="stat-rejected">0</div>
            <div class="stat-label">Rejected</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="color:var(--yellow)" id="stat-hitl">0</div>
            <div class="stat-label">HITL Escalated</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" style="color:var(--blue)" id="stat-vms">0</div>
            <div class="stat-label">Active VMs</div>
          </div>
          <div class="stat-card">
            <div class="stat-value" id="stat-uptime">0s</div>
            <div class="stat-label">Uptime</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Tasks Panel -->
    <div class="panel">
      <div class="panel-header">
        🔍 Analysis Tasks
        <span class="badge badge-blue" id="task-count">0</span>
      </div>
      <div class="panel-body">
        <div class="analyze-form">
          <input type="text" id="repo-url" placeholder="https://github.com/owner/repo" />
          <button class="btn" onclick="triggerAnalysis()">Analyze</button>
        </div>
        <div id="tasks-list"></div>
      </div>
    </div>
    
    <!-- VM Grid -->
    <div class="panel">
      <div class="panel-header">
        ⚡ MicroVM Inventory
        <span class="badge badge-green" id="vm-count">0 active</span>
      </div>
      <div class="panel-body">
        <div class="vm-grid" id="vm-grid">
          <div class="empty-state">No active VMs</div>
        </div>
      </div>
    </div>
    
    <!-- Event Log -->
    <div class="panel" style="grid-column: 1 / -1; max-height: 300px;">
      <div class="panel-header">
        📋 Security Event Log
        <span class="badge badge-blue" id="event-count">0</span>
      </div>
      <div class="panel-body">
        <div class="event-log" id="event-log">
          <div class="empty-state">Awaiting events...</div>
        </div>
      </div>
    </div>
  </main>

  <script>
    let ws = null;
    let stats = {};
    let tasks = [];
    let vms = [];
    let events = [];
    let startTime = Date.now();

    function connect() {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${proto}//${location.host}/ws`);
      
      ws.onopen = () => {
        document.getElementById('conn-status').textContent = '🟢 Connected';
        document.getElementById('conn-status').className = 'badge badge-green';
      };
      
      ws.onclose = () => {
        document.getElementById('conn-status').textContent = '🔴 Reconnecting...';
        document.getElementById('conn-status').className = 'badge badge-red';
        setTimeout(connect, 2000);
      };
      
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        handleMessage(msg);
      };
      
      // Keepalive
      setInterval(() => ws && ws.readyState === 1 && ws.send('ping'), 20000);
    }
    
    function handleMessage(msg) {
      if (msg.type === 'init') {
        stats = msg.data.stats || {};
        tasks = msg.data.active_tasks || [];
        vms = msg.data.active_vms || [];
        events = msg.data.events || [];
        startTime = (stats.start_time || Date.now()/1000) * 1000;
        renderAll();
        return;
      }
      
      events.unshift(msg);
      if (events.length > 200) events.pop();
      
      if (msg.type === 'task_complete' || msg.type === 'task_started' || msg.type === 'task_failed') {
        const d = msg.data;
        const existing = tasks.findIndex(t => t.task_id === d.task_id);
        if (existing >= 0) tasks[existing] = {...tasks[existing], ...d};
        else tasks.unshift(d);
        if (tasks.length > 20) tasks.pop();
      }
      
      if (msg.type === 'vm_created') {
        vms.push(msg.data);
      } else if (msg.type === 'vm_terminated') {
        vms = vms.filter(v => v.vm_id !== msg.data.vm_id);
      }
      
      // Update stats from events
      if (msg.type === 'task_complete') {
        stats.total_tasks = (stats.total_tasks || 0) + (tasks.length > 0 ? 0 : 1);
        if (msg.data.decision === 'APPROVE') stats.approved = (stats.approved || 0) + 1;
        else if (msg.data.decision === 'REJECT') stats.rejected = (stats.rejected || 0) + 1;
        if (msg.data.hitl_required) stats.hitl_escalated = (stats.hitl_escalated || 0) + 1;
      }
      
      renderAll();
    }
    
    function renderAll() {
      renderStats();
      renderTasks();
      renderVMs();
      renderEvents();
    }
    
    function renderStats() {
      document.getElementById('stat-total').textContent = stats.total_tasks || 0;
      document.getElementById('stat-approved').textContent = stats.approved || 0;
      document.getElementById('stat-rejected').textContent = stats.rejected || 0;
      document.getElementById('stat-hitl').textContent = stats.hitl_escalated || 0;
      document.getElementById('stat-vms').textContent = vms.filter(v => v.status === 'running').length;
      
      const uptime = Math.floor((Date.now() - startTime) / 1000);
      const h = Math.floor(uptime / 3600), m = Math.floor((uptime % 3600) / 60), s = uptime % 60;
      document.getElementById('stat-uptime').textContent = h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
    }
    
    function renderTasks() {
      const el = document.getElementById('tasks-list');
      document.getElementById('task-count').textContent = tasks.length;
      
      if (!tasks.length) {
        el.innerHTML = '<div class="empty-state">No tasks yet. Enter a GitHub URL above.</div>';
        return;
      }
      
      el.innerHTML = tasks.slice(0, 10).map(t => {
        const risk = t.aggregate_risk || 0;
        const riskClass = risk > 0.7 ? 'risk-3' : risk > 0.4 ? 'risk-2' : risk > 0.2 ? 'risk-1' : 'risk-0';
        const decisionBadge = t.decision === 'APPROVE' ? 'badge-green' :
          t.decision === 'REJECT' ? 'badge-red' :
          t.status === 'running' ? 'badge-blue' : 'badge-yellow';
        const decisionText = t.decision || t.status || 'pending';
        
        return `
          <div class="task-item">
            <div class="task-header">
              <span class="task-id">${t.task_id || 'unknown'}</span>
              <span class="badge ${decisionBadge}">${decisionText.toUpperCase()}</span>
            </div>
            <div style="font-size:11px; color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
              ${(t.repo_url || '').replace('https://github.com/', '⎇ ')}
            </div>
            ${risk > 0 ? `
            <div class="risk-bar"><div class="risk-fill ${riskClass}" style="width:${(risk*100).toFixed(0)}%"></div></div>
            <div class="task-meta">
              <span>Risk: ${(risk*100).toFixed(0)}%</span>
              <span>${t.total_files || 0} files</span>
              <span>${t.high_risk_files || 0} high-risk</span>
              ${t.hitl_required ? '<span style="color:var(--yellow)">⚠ HITL</span>' : ''}
              ${t.duration_seconds ? `<span>${t.duration_seconds.toFixed(1)}s</span>` : ''}
            </div>` : ''}
          </div>
        `;
      }).join('');
    }
    
    function renderVMs() {
      const el = document.getElementById('vm-grid');
      const active = vms.filter(v => v.status !== 'terminated');
      document.getElementById('vm-count').textContent = `${active.filter(v => v.status === 'running').length} active`;
      
      if (!active.length) {
        el.innerHTML = '<div class="empty-state">No active VMs</div>';
        return;
      }
      
      const roleColors = {
        secure_fetcher: '#388bfd', ast_parser: '#3fb950', ir_builder: '#bc8cff',
        ml_analyzer: '#d2844f', policy_engine: '#d29922', iac_generator: '#6ab0f5',
      };
      
      el.innerHTML = active.map(vm => {
        const color = roleColors[vm.role] || '#8b949e';
        const dotClass = vm.status === 'running' ? 'dot-running' : 'dot-terminating';
        const age = vm.age_seconds ? `${Math.floor(vm.age_seconds)}s` : '—';
        return `
          <div class="vm-card ${vm.status}">
            <div class="vm-role" style="color:${color}">
              <span class="vm-status-dot ${dotClass}"></span>
              ${(vm.role || '').replace('_', ' ')}
            </div>
            <div class="vm-id">${vm.vm_id || vm.azure_vm_name || ''}</div>
            <div class="vm-id">${vm.private_ip || ''}</div>
            <div class="vm-age">⏱ ${age}</div>
          </div>
        `;
      }).join('');
    }
    
    function renderEvents() {
      const el = document.getElementById('event-log');
      document.getElementById('event-count').textContent = events.length;
      
      if (!events.length) {
        el.innerHTML = '<div class="empty-state">Awaiting events...</div>';
        return;
      }
      
      el.innerHTML = events.slice(0, 100).map(ev => {
        const t = new Date((ev.timestamp || Date.now()/1000) * 1000);
        const timeStr = t.toTimeString().slice(0, 8);
        const sev = ev.severity || 'info';
        const data = typeof ev.data === 'object' ?
          JSON.stringify(ev.data).replace(/"/g, '').slice(0, 80) :
          String(ev.data || '');
        return `
          <div class="event-item">
            <span class="event-time">${timeStr}</span>
            <span class="event-type ${sev}">${ev.type || 'unknown'}</span>
            <span class="event-data">${data}</span>
          </div>
        `;
      }).join('');
    }
    
    async function triggerAnalysis() {
      const url = document.getElementById('repo-url').value.trim();
      if (!url) return;
      
      try {
        const resp = await fetch('/api/analyze', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({repo_url: url}),
        });
        const data = await resp.json();
        console.log('Analysis started:', data);
        document.getElementById('repo-url').value = '';
      } catch (e) {
        console.error('Analysis failed:', e);
      }
    }
    
    document.getElementById('repo-url').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') triggerAnalysis();
    });
    
    // Refresh stats every second
    setInterval(renderStats, 1000);
    
    connect();
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    """Serve monitoring dashboard."""
    return DASHBOARD_HTML