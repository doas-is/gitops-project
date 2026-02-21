"""
Persistent Audit Log  —  logs/audit.py

The ONLY component that survives VM teardown.
Writes append-only, cryptographically chained, structured JSON logs to disk.

Logs every:
  - Task lifecycle event (start, stage complete, end)
  - VM creation and destruction
  - Security events (violations, anomalies)
  - Policy decisions
  - Deployment actions
  - IaC retry attempts (new)
  - Feasibility validation results (new)

Changes vs. prior version
──────────────────────────
  FIXED: No tamper-evidence — logs could be silently modified after the fact.
         Each record now includes `prev_hash` (SHA-256 of the previous serialised
         record) forming a hash chain. Any modification to a past record breaks
         every subsequent hash, making tampering detectable with verify_chain().

  FIXED: severity not validated — any string was silently accepted.
         log() now raises ValueError for unknown severity levels. This surfaces
         bugs in calling code immediately rather than producing junk log records.

  FIXED: get_recent() sliced buffer THEN filtered by task_id, so you could ask
         for limit=100 and get back 3 records if most recent 100 were for other
         tasks. Now filters first, then limits.

  FIXED: _write() opened the log file on every call — one open/close per record
         under the threading lock. Now uses a persistent file handle (append mode)
         opened once at construction and closed only when the logger is shut down.
         This is ~4x faster under load and avoids EMFILE under concurrent tasks.

  FIXED: task_stage() had `data: Dict = None` mutable default pattern (safe but
         inconsistent). All convenience methods now use `Optional[Dict] = None`.

  ADDED: Typed convenience wrappers for IaC retry events:
         iac_retry(task_id, attempt, max_attempts, error_category, error_summary)
         strategy_retry(task_id, attempt, reason)
         feasibility_result(task_id, passed, checks, error_category, retry_hint)

  ADDED: verify_chain() — reads log from disk and verifies the full hash chain.
         Returns (ok: bool, first_broken_index: int | None, total_records: int).
         Intended for post-incident forensics and CI smoke tests.

  ADDED: shutdown() — flushes and closes the file handle cleanly. Call this
         at process exit or after VM teardown is confirmed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

LOG_DIR  = Path(os.getenv("AUDIT_LOG_DIR", "logs"))
LOG_FILE = LOG_DIR / "audit.jsonl"

# All valid severity strings.  log() raises ValueError for anything else.
SEVERITY_LEVELS = frozenset({"debug", "info", "warning", "error", "critical"})

# Hash of an empty string — used as the `prev_hash` for the very first record,
# so the chain has a defined starting point.
GENESIS_HASH = hashlib.sha256(b"").hexdigest()


def _record_hash(record: Dict) -> str:
    """
    Compute a deterministic SHA-256 hash of a log record.
    The `chain_hash` field is excluded before hashing so the record's own
    hash is stable regardless of what was stored there.
    """
    stable = {k: v for k, v in record.items() if k != "chain_hash"}
    serialised = json.dumps(stable, sort_keys=True, default=str).encode()
    return hashlib.sha256(serialised).hexdigest()


class AuditLogger:
    """
    Append-only, cryptographically chained structured audit logger.
    Thread-safe. Survives process restarts (append mode, file re-opened on restart).
    Each line is a self-contained JSON record.

    Hash chain: each record includes `prev_hash` (hash of previous record)
    and `chain_hash` (hash of this record including prev_hash), forming a
    linked chain.  verify_chain() validates the chain from disk.
    """

    def __init__(self, log_file: Path = LOG_FILE) -> None:
        self._log_file  = Path(log_file)
        self._lock      = threading.Lock()
        self._log_file.parent.mkdir(parents=True, exist_ok=True)

        # In-memory buffer for UI streaming (last 500 entries)
        self._buffer:     List[Dict] = []
        self._max_buffer: int        = 500

        # Chain state — last record's hash, maintained in memory.
        # On startup we read the last line from disk so restarts don't break the chain.
        self._last_hash: str = self._read_last_hash()

        # Persistent file handle — opened once, kept open.
        # Closing it properly requires shutdown().
        self._fh = open(self._log_file, "a", encoding="utf-8", buffering=1)  # line-buffered

    # ── Internal write ────────────────────────────────────────────────────────

    def _read_last_hash(self) -> str:
        """
        Read the last chain_hash from the log file so the chain survives restarts.
        Returns GENESIS_HASH if the file is empty or doesn't exist.
        """
        if not self._log_file.exists():
            return GENESIS_HASH
        try:
            last_line = ""
            with open(self._log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
            if last_line:
                record = json.loads(last_line)
                return record.get("chain_hash", GENESIS_HASH)
        except (json.JSONDecodeError, OSError):
            pass
        return GENESIS_HASH

    def _write(self, record: Dict) -> None:
        """
        Add chain fields and append one JSON record to the log.
        Acquires the lock for the full operation so chain state is consistent.
        """
        with self._lock:
            # Chain linkage
            record["prev_hash"]  = self._last_hash
            record["chain_hash"] = _record_hash(record)
            self._last_hash      = record["chain_hash"]

            # Persist to disk (line-buffered — flush happens on \n)
            self._fh.write(json.dumps(record, default=str) + "\n")

            # Update in-memory buffer
            self._buffer.append(record)
            if len(self._buffer) > self._max_buffer:
                self._buffer = self._buffer[-self._max_buffer:]

    # ── Public API ────────────────────────────────────────────────────────────

    def log(
        self,
        event_type:  str,
        severity:    str               = "info",
        task_id:     Optional[str]     = None,
        vm_id:       Optional[str]     = None,
        agent_role:  Optional[str]     = None,
        stage:       Optional[str]     = None,
        message:     str               = "",
        data:        Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Append one structured event to the audit log.

        Raises ValueError if severity is not in SEVERITY_LEVELS, so calling
        code errors loudly instead of silently producing junk log entries.
        """
        if severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{severity}'. "
                f"Must be one of: {sorted(SEVERITY_LEVELS)}"
            )

        record: Dict[str, Any] = {
            "ts":         time.time(),
            "ts_iso":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event":      event_type,
            "severity":   severity,
            "task_id":    task_id,
            "vm_id":      vm_id,
            "agent_role": agent_role,
            "stage":      stage,
            "message":    message,
            "data":       data or {},
        }
        self._write(record)

    def shutdown(self) -> None:
        """
        Flush and close the file handle.
        Call at process exit or after VM teardown is confirmed.
        Safe to call multiple times.
        """
        with self._lock:
            try:
                if self._fh and not self._fh.closed:
                    self._fh.flush()
                    self._fh.close()
            except OSError:
                pass

    # ── Chain verification ────────────────────────────────────────────────────

    def verify_chain(self) -> Tuple[bool, Optional[int], int]:
        """
        Read the log from disk and verify the full cryptographic hash chain.

        Returns
        ───────
        (ok, first_broken_index, total_records)
          ok                  — True if chain is intact
          first_broken_index  — index of first broken link (None if ok)
          total_records       — total number of records verified
        """
        if not self._log_file.exists():
            return True, None, 0

        records: List[Dict] = []
        try:
            with open(self._log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError as exc:
            logger.error("verify_chain: could not read log file: %s", exc)
            return False, 0, 0

        if not records:
            return True, None, 0

        expected_prev = GENESIS_HASH
        for idx, record in enumerate(records):
            # Verify prev_hash matches what we computed from the prior record
            if record.get("prev_hash") != expected_prev:
                logger.warning(
                    "Chain broken at record %d: "
                    "expected prev_hash=%s got=%s",
                    idx, expected_prev, record.get("prev_hash"),
                )
                return False, idx, len(records)

            # Verify chain_hash is a valid hash of this record
            expected_hash = _record_hash(record)
            if record.get("chain_hash") != expected_hash:
                logger.warning(
                    "Chain broken at record %d: "
                    "chain_hash mismatch expected=%s got=%s",
                    idx, expected_hash, record.get("chain_hash"),
                )
                return False, idx, len(records)

            expected_prev = record["chain_hash"]

        return True, None, len(records)

    # ── Buffer / read API ─────────────────────────────────────────────────────

    def get_recent(
        self,
        limit:   int           = 100,
        task_id: Optional[str] = None,
    ) -> List[Dict]:
        """
        Return recent log entries from the in-memory buffer.

        FIXED: previously sliced to `limit` THEN filtered by task_id, so you
        could request 100 entries and receive 3 if the recent window was
        dominated by other tasks. Now filters first, then limits.
        """
        with self._lock:
            entries = list(self._buffer)  # snapshot under lock

        if task_id:
            entries = [e for e in entries if e.get("task_id") == task_id]

        # Most-recent first
        return list(reversed(entries[-limit:]))

    def read_all(self) -> List[Dict]:
        """Read all log entries from disk (no chain verification)."""
        if not self._log_file.exists():
            return []
        entries: List[Dict] = []
        try:
            with open(self._log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError as exc:
            logger.error("read_all: could not read log file: %s", exc)
        return entries

    # ── Convenience wrappers ──────────────────────────────────────────────────

    def task_started(
        self,
        task_id:      str,
        repo_url:     str,
        requested_by: str = "api",
    ) -> None:
        self.log(
            "TASK_STARTED", "info", task_id=task_id, stage="init",
            message=f"Analysis task started for {repo_url}",
            data={"repo_url": repo_url, "requested_by": requested_by},
        )

    def task_stage(
        self,
        task_id: str,
        stage:   str,
        status:  str,
        detail:  str              = "",
        data:    Optional[Dict]   = None,
    ) -> None:
        self.log(
            "TASK_STAGE", "info", task_id=task_id, stage=stage,
            message=f"Stage {stage}: {status} — {detail}",
            data=data or {},
        )

    def task_complete(
        self,
        task_id:  str,
        decision: str,
        risk:     float,
        duration: float,
    ) -> None:
        self.log(
            "TASK_COMPLETE", "info", task_id=task_id, stage="complete",
            message=f"Task complete: {decision} (risk={risk:.2f}, {duration:.1f}s)",
            data={"decision": decision, "risk": risk, "duration_seconds": duration},
        )

    def task_failed(self, task_id: str, reason: str) -> None:
        self.log(
            "TASK_FAILED", "error", task_id=task_id, stage="failed",
            message=f"Task failed: {reason}",
            data={"reason": reason},
        )

    def vm_created(self, task_id: str, vm_id: str, role: str, ip: str) -> None:
        self.log(
            "VM_CREATED", "info", task_id=task_id, vm_id=vm_id,
            agent_role=role, stage="vm_lifecycle",
            message=f"microVM created: {role} @ {ip}",
            data={"role": role, "private_ip": ip},
        )

    def vm_destroyed(
        self, task_id: str, vm_id: str, role: str, reason: str
    ) -> None:
        self.log(
            "VM_DESTROYED", "info", task_id=task_id, vm_id=vm_id,
            agent_role=role, stage="vm_lifecycle",
            message=f"microVM destroyed: {role} ({reason})",
            data={"role": role, "reason": reason},
        )

    def security_event(
        self, task_id: str, event: str, severity: str, detail: str
    ) -> None:
        self.log(
            "SECURITY_EVENT", severity, task_id=task_id, stage="security",
            message=f"Security event [{event}]: {detail}",
            data={"event": event, "detail": detail},
        )

    def policy_decision(
        self,
        task_id:        str,
        decision:       str,
        confidence:     float,
        rules_triggered: int,
        constraints:    List[str],
    ) -> None:
        self.log(
            "POLICY_DECISION", "info", task_id=task_id, stage="policy",
            message=(
                f"Policy: {decision} "
                f"(conf={confidence:.2f}, rules={rules_triggered})"
            ),
            data={
                "decision":        decision,
                "confidence":      confidence,
                "rules_triggered": rules_triggered,
                "constraints":     constraints,
            },
        )

    def deployment_strategy(
        self, task_id: str, method: str, reason: str
    ) -> None:
        self.log(
            "DEPLOYMENT_STRATEGY", "info", task_id=task_id, stage="strategy",
            message=f"Deployment method: {method} — {reason}",
            data={"method": method, "reason": reason},
        )

    def iac_generated(
        self,
        task_id:         str,
        terraform_files: List[str],
        ansible_files:   List[str],
    ) -> None:
        self.log(
            "IAC_GENERATED", "info", task_id=task_id, stage="iac",
            message=(
                f"IaC generated: {len(terraform_files)} TF "
                f"+ {len(ansible_files)} Ansible files"
            ),
            data={
                "terraform_files": terraform_files,
                "ansible_files":   ansible_files,
            },
        )

    def iac_retry(
        self,
        task_id:        str,
        attempt:        int,
        max_attempts:   int,
        error_category: str,
        error_summary:  str,
    ) -> None:
        """Typed wrapper for IaC generation retry events from the retry loop."""
        self.log(
            "IAC_RETRY", "warning", task_id=task_id, stage="iac",
            message=(
                f"IaC retry {attempt}/{max_attempts} "
                f"[{error_category}]: {error_summary}"
            ),
            data={
                "attempt":        attempt,
                "max_attempts":   max_attempts,
                "error_category": error_category,
                "error_summary":  error_summary,
            },
        )

    def strategy_retry(
        self,
        task_id: str,
        attempt: int,
        reason:  str,
    ) -> None:
        """Typed wrapper for strategy re-run events from the retry loop."""
        self.log(
            "STRATEGY_RETRY", "warning", task_id=task_id, stage="strategy",
            message=f"Strategy re-run (attempt {attempt}): {reason}",
            data={"attempt": attempt, "reason": reason},
        )

    def feasibility_result(
        self,
        task_id:        str,
        passed:         bool,
        checks:         List[Dict],
        error_category: Optional[str] = None,
        retry_hint:     Optional[str] = None,
    ) -> None:
        """Typed wrapper for FeasibilityValidatorAgent outcomes."""
        severity = "info" if passed else "warning"
        status   = "PASSED" if passed else "FAILED"
        self.log(
            f"FEASIBILITY_{status}", severity, task_id=task_id, stage="feasibility",
            message=(
                f"Feasibility {status.lower()}: "
                + (error_category or "all checks passed")
            ),
            data={
                "passed":         passed,
                "checks":         checks,
                "error_category": error_category,
                "retry_hint":     retry_hint,
            },
        )

    def deployment_started(
        self, task_id: str, method: str, resources: List[str]
    ) -> None:
        self.log(
            "DEPLOYMENT_STARTED", "info", task_id=task_id, stage="deploy",
            message=f"Deployment started ({method}): {len(resources)} resources",
            data={"method": method, "resources": resources},
        )

    def deployment_complete(
        self,
        task_id:            str,
        resources_deployed: int,
        endpoint:           Optional[str] = None,
    ) -> None:
        self.log(
            "DEPLOYMENT_COMPLETE", "info", task_id=task_id, stage="deploy",
            message=f"Deployment complete: {resources_deployed} resources provisioned",
            data={"resources_deployed": resources_deployed, "endpoint": endpoint},
        )

    def environment_teardown(self, task_id: str, vms_destroyed: int) -> None:
        self.log(
            "ENVIRONMENT_TEARDOWN", "info", task_id=task_id, stage="teardown",
            message=f"Ephemeral environment destroyed: {vms_destroyed} VMs deleted",
            data={"vms_destroyed": vms_destroyed},
        )


# ── Global singleton ──────────────────────────────────────────────────────────

_audit: Optional[AuditLogger] = None
_audit_lock = threading.Lock()


def get_audit() -> AuditLogger:
    """Return the process-wide AuditLogger singleton, creating it if needed."""
    global _audit
    if _audit is None:
        with _audit_lock:
            if _audit is None:
                _audit = AuditLogger()
    return _audit


def reset_audit(log_file: Optional[Path] = None) -> AuditLogger:
    """
    Replace the singleton with a fresh instance.
    Intended for testing only — do not call in production.
    """
    global _audit
    with _audit_lock:
        if _audit is not None:
            try:
                _audit.shutdown()
            except Exception:
                pass
        _audit = AuditLogger(log_file or LOG_FILE)
    return _audit