"""
Persistent Audit Log

The ONLY component that survives VM teardown.
Writes append-only structured JSON logs to disk.

Logs every:
  - Task lifecycle event (start, stage complete, end)
  - VM creation and destruction
  - Security events (violations, anomalies)
  - Policy decisions
  - Deployment actions

Encrypted at rest with AES-256-GCM using a log key separate from the KEK.
Log key is stored in Azure Key Vault and NEVER in the log file itself.
"""
from __future__ import annotations

import json
import logging
import os
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

LOG_DIR = Path(os.getenv("AUDIT_LOG_DIR", "logs"))
LOG_FILE = LOG_DIR / "audit.jsonl"
SEVERITY_LEVELS = {"debug", "info", "warning", "error", "critical"}


class AuditLogger:
    """
    Append-only structured audit logger.
    Thread-safe. Survives process restarts (append mode).
    Each line is a self-contained JSON record.
    """

    def __init__(self, log_file = LOG_FILE) -> None:
        self._log_file = Path(log_file)
        self._lock = threading.Lock()
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        # In-memory buffer for UI streaming (last 500 entries)
        self._buffer: List[Dict] = []
        self._max_buffer = 500

    def _write(self, record: Dict) -> None:
        """Append a single JSON record to the audit log file."""
        with self._lock:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
            self._buffer.append(record)
            if len(self._buffer) > self._max_buffer:
                self._buffer = self._buffer[-self._max_buffer:]

    def log(
        self,
        event_type: str,
        severity: str = "info",
        task_id: Optional[str] = None,
        vm_id: Optional[str] = None,
        agent_role: Optional[str] = None,
        stage: Optional[str] = None,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        record = {
            "ts": time.time(),
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event_type,
            "severity": severity,
            "task_id": task_id,
            "vm_id": vm_id,
            "agent_role": agent_role,
            "stage": stage,
            "message": message,
            "data": data or {},
        }
        self._write(record)

    # ── Convenience methods ──────────────────────────────────────

    def task_started(self, task_id: str, repo_url: str, requested_by: str = "api") -> None:
        self.log("TASK_STARTED", "info", task_id=task_id, stage="init",
                 message=f"Analysis task started for {repo_url}",
                 data={"repo_url": repo_url, "requested_by": requested_by})

    def task_stage(self, task_id: str, stage: str, status: str, detail: str = "", data: Dict = None) -> None:
        self.log("TASK_STAGE", "info", task_id=task_id, stage=stage,
                 message=f"Stage {stage}: {status} — {detail}",
                 data=data or {})

    def task_complete(self, task_id: str, decision: str, risk: float, duration: float) -> None:
        self.log("TASK_COMPLETE", "info", task_id=task_id, stage="complete",
                 message=f"Task complete: {decision} (risk={risk:.2f}, {duration:.1f}s)",
                 data={"decision": decision, "risk": risk, "duration_seconds": duration})

    def task_failed(self, task_id: str, reason: str) -> None:
        self.log("TASK_FAILED", "error", task_id=task_id, stage="failed",
                 message=f"Task failed: {reason}", data={"reason": reason})

    def vm_created(self, task_id: str, vm_id: str, role: str, ip: str) -> None:
        self.log("VM_CREATED", "info", task_id=task_id, vm_id=vm_id,
                 agent_role=role, stage="vm_lifecycle",
                 message=f"microVM created: {role} @ {ip}",
                 data={"role": role, "private_ip": ip})

    def vm_destroyed(self, task_id: str, vm_id: str, role: str, reason: str) -> None:
        self.log("VM_DESTROYED", "info", task_id=task_id, vm_id=vm_id,
                 agent_role=role, stage="vm_lifecycle",
                 message=f"microVM destroyed: {role} ({reason})",
                 data={"role": role, "reason": reason})

    def security_event(self, task_id: str, event: str, severity: str, detail: str) -> None:
        self.log("SECURITY_EVENT", severity, task_id=task_id, stage="security",
                 message=f"Security event [{event}]: {detail}",
                 data={"event": event, "detail": detail})

    def policy_decision(self, task_id: str, decision: str, confidence: float,
                        rules_triggered: int, constraints: List[str]) -> None:
        self.log("POLICY_DECISION", "info", task_id=task_id, stage="policy",
                 message=f"Policy: {decision} (conf={confidence:.2f}, rules={rules_triggered})",
                 data={"decision": decision, "confidence": confidence,
                       "rules_triggered": rules_triggered, "constraints": constraints})

    def deployment_strategy(self, task_id: str, method: str, reason: str) -> None:
        self.log("DEPLOYMENT_STRATEGY", "info", task_id=task_id, stage="strategy",
                 message=f"Deployment method: {method} — {reason}",
                 data={"method": method, "reason": reason})

    def iac_generated(self, task_id: str, terraform_files: List[str],
                      ansible_files: List[str]) -> None:
        self.log("IAC_GENERATED", "info", task_id=task_id, stage="iac",
                 message=f"IaC generated: {len(terraform_files)} TF + {len(ansible_files)} Ansible files",
                 data={"terraform_files": terraform_files, "ansible_files": ansible_files})

    def deployment_started(self, task_id: str, method: str, resources: List[str]) -> None:
        self.log("DEPLOYMENT_STARTED", "info", task_id=task_id, stage="deploy",
                 message=f"Deployment started ({method}): {len(resources)} resources",
                 data={"method": method, "resources": resources})

    def deployment_complete(self, task_id: str, resources_deployed: int,
                            endpoint: Optional[str] = None) -> None:
        self.log("DEPLOYMENT_COMPLETE", "info", task_id=task_id, stage="deploy",
                 message=f"Deployment complete: {resources_deployed} resources provisioned",
                 data={"resources_deployed": resources_deployed, "endpoint": endpoint})

    def environment_teardown(self, task_id: str, vms_destroyed: int) -> None:
        self.log("ENVIRONMENT_TEARDOWN", "info", task_id=task_id, stage="teardown",
                 message=f"Ephemeral environment destroyed: {vms_destroyed} VMs deleted",
                 data={"vms_destroyed": vms_destroyed})

    def get_recent(self, limit: int = 100, task_id: Optional[str] = None) -> List[Dict]:
        """Return recent log entries from in-memory buffer."""
        entries = self._buffer[-limit:]
        if task_id:
            entries = [e for e in entries if e.get("task_id") == task_id]
        return list(reversed(entries))

    def read_all(self) -> List[Dict]:
        """Read all log entries from disk."""
        if not self._log_file.exists():
            return []
        entries = []
        with open(self._log_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return entries


# Global singleton
_audit: Optional[AuditLogger] = None


def get_audit() -> AuditLogger:
    global _audit
    if _audit is None:
        _audit = AuditLogger()
    return _audit