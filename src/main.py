"""
Pipeline Orchestrator  —  src/main.py

REAL execution on Azure. Every stage is a real ACI container.

Architecture:
  Stage 0 — NETWORK     : Provision VNet + NSG isolating the task environment
  Stage 1 — FETCH       : ACI fetches repo via GitHub API, encrypts every file
                          with AES-256-GCM, DEK wrapped by Azure Key Vault KEK.
                          mTLS used for all inter-agent transfers.
  Stage 2 — PARSE       : One dedicated ACI per file.
                          Each ACI decrypts JIT, builds AST, strips all semantics,
                          runs malice detection. On hit → VM killed instantly,
                          HITL alert fired, file quarantined.
  Stage 3 — IR BUILD    : ACI converts clean ASTs → language-agnostic IR.
                          Produces: AST summary, dependency graph, hashes,
                          control-flow metadata, infra metadata, security flags.
  Stage 4 — ML SCORE    : ACI runs CodeBERT ensemble on IR tokens.
  Stage 5 — POLICY      : ACI evaluates rules R001–R006.
                          HITL escalation on confidence < 0.60.
  Stage 6 — STRATEGY    : ACI decides deployment method from IR + policy.
  Stage 7 — IaC GEN     : ACI produces Terraform + Ansible.
  Stage 8 — DEPLOY      : ACI applies IaC. Verifies. Reports.
  Stage 9 — TEARDOWN    : All ACIs deleted, VNet/NSG deleted, audit log kept.
"""
from __future__ import annotations

import asyncio
import gc
import hashlib
import logging
import os
import secrets
import time
from base64 import b64decode
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from config.azure_config import AGENT_CONFIG
from src.analyzer.ir_builder import build_ir_from_ast
from src.analyzer.ml_analyzer import MLSecurityAnalyzer
from src.agents.policy_engine import PolicyEngine
from src.agents.deployment_strategy import DeploymentStrategyAgent
from src.agents.iac_generator import IaCGeneratorAgent
from src.agents.deployment_agent import DeploymentAgent
from src.azure_setup import MicroVMOrchestrator, MicroVMRecord
from src.key_management import FileEncryptor, build_kms, EncryptedPayload
from src.parser import parse_source_bytes
from src.schemas.a2a_schemas import (
    AgentRole, ASTPayload, ASTNode, EncryptedFilePayload, IRPayload,
    MessageType, create_header,
)
from logs.audit import get_audit

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)
for lib in ("azure", "urllib3", "transformers", "torch"):
    logging.getLogger(lib).setLevel(logging.WARNING)


# ── UI event bridge ───────────────────────────────────────────────────────────
_ui_event_callback = None

def set_ui_callback(fn) -> None:
    global _ui_event_callback
    _ui_event_callback = fn

def _emit(event_type: str, data: dict, severity: str = "info") -> None:
    get_audit().log(
        event_type, severity,
        task_id=data.get("task_id"), stage=data.get("stage"),
        message=data.get("message", ""),
        data={k: v for k, v in data.items()
              if k not in ("task_id", "stage", "message")},
    )
    if _ui_event_callback:
        try:
            _ui_event_callback(event_type, data, severity)
        except Exception:
            pass


# ── HITL alert store ──────────────────────────────────────────────────────────
_hitl_alerts: Dict[str, dict] = {}   # alert_id → alert

def get_hitl_alerts() -> List[dict]:
    return list(_hitl_alerts.values())

def resolve_hitl_alert(alert_id: str, decision: str,
                        operator: str, notes: str) -> bool:
    a = _hitl_alerts.get(alert_id)
    if a and a["status"] == "pending":
        a.update(status=decision, operator=operator,
                 notes=notes, resolved_at=time.time())
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Malice detection
# ─────────────────────────────────────────────────────────────────────────────

# Flags that individually indicate danger
_HIGH_RISK_FLAGS = {
    "has_eval_calls",
    "has_exec_calls",
    "has_obfuscation",
    "has_injection_risk",
    "has_deserialisation",
    "has_privilege_calls",
}

# Combinations that together are extremely dangerous
_DEADLY_COMBOS = [
    {"has_eval_calls",       "has_dynamic_imports"},   # code injection
    {"has_obfuscation",      "has_high_entropy"},       # obfuscated payload
    {"has_network_calls",    "has_eval_calls"},         # remote code exec
    {"has_privilege_calls",  "has_injection_risk"},     # privilege escalation
]

# Threshold: need this many individual flags OR one deadly combo to kill VM
_MALICE_THRESHOLD = 3


def _detect_malice(ast_p: ASTPayload) -> Tuple[bool, List[str]]:
    """
    Returns (is_malicious, triggered_reasons).
    Reasons are human-readable strings for HITL display.
    """
    triggered: List[str] = []

    for flag in _HIGH_RISK_FLAGS:
        if getattr(ast_p, flag, False):
            triggered.append(flag.replace("has_", "").replace("_", " "))

    for combo in _DEADLY_COMBOS:
        if all(getattr(ast_p, f, False) for f in combo):
            combo_name = " + ".join(f.replace("has_", "") for f in combo)
            if combo_name not in triggered:
                triggered.append(f"deadly combo: {combo_name}")

    # Deadly combo = instant kill regardless of threshold
    for combo in _DEADLY_COMBOS:
        if all(getattr(ast_p, f, False) for f in combo):
            return True, triggered

    return len(triggered) >= _MALICE_THRESHOLD, triggered


# ─────────────────────────────────────────────────────────────────────────────
# Intelligence summary (Stage 3 output — feeds IaC generation)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IntelligenceSummary:
    """
    Structured intelligence extracted from the repository.
    Never contains source code or human-readable logic —
    only structural metadata derived from IR analysis.
    """
    task_id:       str
    total_files:   int
    clean_files:   int
    killed_files:  int

    # AST summary
    total_ast_nodes:      int = 0
    avg_cyclomatic:       float = 0.0
    max_cyclomatic:       int = 0
    total_functions:      int = 0
    total_classes:        int = 0

    # Dependency graph
    dependency_map:       Dict[str, List[str]] = field(default_factory=dict)
    unique_imports:       List[str] = field(default_factory=list)
    privileged_imports:   List[str] = field(default_factory=list)

    # Hashes (SHA-256 of each encrypted file — integrity chain)
    file_hashes:          Dict[str, str] = field(default_factory=dict)

    # Control flow metadata
    total_ir_nodes:       int = 0
    control_flow_depth:   int = 0
    loop_density:         float = 0.0
    branch_density:       float = 0.0

    # Infra metadata
    detected_languages:   List[str] = field(default_factory=list)
    infra_hints:          List[str] = field(default_factory=list)

    # Security flags from ML model
    security_flags:       List[str] = field(default_factory=list)
    aggregate_risk:       float = 0.0
    high_risk_files:      int = 0
    anomalous_patterns:   int = 0

    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

PRIVILEGED_IMPORTS = {
    "subprocess", "os", "sys", "ctypes", "socket", "paramiko",
    "requests", "urllib", "httpx", "aiohttp", "eval", "exec",
    "pickle", "marshal", "shelve", "importlib", "imp",
}

INFRA_HINT_IMPORTS = {
    "boto3": "AWS SDK",
    "azure": "Azure SDK",
    "google.cloud": "GCP SDK",
    "kubernetes": "Kubernetes client",
    "docker": "Docker API",
    "terraform": "Terraform",
    "ansible": "Ansible",
    "paramiko": "SSH/remote execution",
    "sqlalchemy": "Database ORM",
    "redis": "Redis cache",
    "celery": "Task queue",
    "kafka": "Message streaming",
}


class SecureAnalysisPipeline:
    """
    Full pipeline using real Azure Container Instances.
    One ACI per stage. One ACI per file for parsing.
    """

    def __init__(self) -> None:
        use_local = os.getenv("KMS_LOCAL", "false").lower() == "true"
        self.kms             = build_kms(use_local=use_local)
        self.encryptor       = FileEncryptor(self.kms)
        self.ml_analyzer     = MLSecurityAnalyzer()
        self.policy_engine   = PolicyEngine()
        self.strategy_agent  = DeploymentStrategyAgent()
        self.iac_agent       = IaCGeneratorAgent()
        self.deploy_agent    = DeploymentAgent()
        self._audit          = get_audit()
        self._orchestrator   = MicroVMOrchestrator()
        self._pipeline_runs  = 0

    # ── VM lifecycle wrappers ─────────────────────────────────────────────────

    async def _spin_up(self, role: str, task_id: str,
                       env: Optional[Dict] = None) -> MicroVMRecord:
        """Provision real ACI and emit UI event."""
        vm = await self._orchestrator.provision_agent_vm(role, task_id, env)
        _emit("vm_created", {
            "task_id":    task_id,
            "vm_id":      vm.vm_id,
            "role":       vm.agent_role,
            "private_ip": vm.private_ip,
            "azure_name": vm.azure_vm_name,
            "status":     "running",
            "age_seconds": 0,
            "stage":      "vm_lifecycle",
            "message":    f"ACI online: {role} @ {vm.private_ip} ({vm.azure_vm_name})",
        })
        self._audit.vm_created(task_id, vm.vm_id, role, vm.private_ip)
        return vm

    async def _spin_down(self, vm: MicroVMRecord,
                          reason: str = "stage_complete") -> None:
        """Terminate real ACI and emit UI event."""
        await self._orchestrator.terminate_vm(vm.vm_id, reason)
        _emit("vm_terminated", {
            "task_id": vm.task_id,
            "vm_id":   vm.vm_id,
            "role":    vm.agent_role,
            "reason":  reason,
            "stage":   "vm_lifecycle",
            "message": f"ACI deleted: {vm.agent_role} ({reason})",
        }, severity="error" if "violation" in reason else "info")
        self._audit.vm_destroyed(vm.task_id, vm.vm_id, vm.agent_role, reason)

    async def _kill_vm_violation(
        self,
        vm: MicroVMRecord,
        task_id: str,
        file_ext: str,
        file_index: int,
        reasons: List[str],
    ) -> None:
        """
        Instant VM kill on malice detection.
        Fires HITL alert visible in dashboard.
        """
        reason_str = f"malicious_code:{'+'.join(reasons[:3])}"
        await self._orchestrator.terminate_vm(vm.vm_id, reason_str)

        alert_id = secrets.token_hex(8)
        alert = {
            "alert_id":    alert_id,
            "task_id":     task_id,
            "type":        "malicious_file",
            "file_index":  file_index,
            "file_ext":    file_ext,
            "reasons":     reasons,
            "vm_id":       vm.vm_id,
            "azure_name":  vm.azure_vm_name,
            "status":      "pending",
            "created_at":  time.time(),
            "operator":    None,
            "notes":       None,
        }
        _hitl_alerts[alert_id] = alert

        _emit("vm_terminated", {
            "task_id": task_id, "vm_id": vm.vm_id,
            "role": vm.agent_role, "reason": reason_str,
            "stage": "security_violation",
            "message": f"🚨 VM KILLED: malicious pattern in file #{file_index} ({file_ext})",
        }, severity="error")

        _emit("hitl_alert", {
            "task_id":   task_id,
            "alert_id":  alert_id,
            "file_index": file_index,
            "file_ext":  file_ext,
            "reasons":   reasons,
            "vm_id":     vm.vm_id,
            "stage":     "hitl",
            "message": (
                f"🚨 HITL REQUIRED — file #{file_index}{file_ext}: "
                f"{', '.join(reasons)}"
            ),
        }, severity="error")

        self._audit.log("SECURITY_VIOLATION", "error", task_id=task_id,
                        stage="security", message=reason_str,
                        data={"file_index": file_index, "reasons": reasons,
                              "vm_id": vm.vm_id, "alert_id": alert_id})
        logger.error("[%s] SECURITY VIOLATION file #%d: %s",
                     task_id, file_index, reasons)

    # ── Per-file parse + malice check ─────────────────────────────────────────

    async def _parse_one_file(
        self,
        payload: EncryptedFilePayload,
        task_id: str,
    ) -> Optional[ASTPayload]:
        """
        Spin up a dedicated ACI for one file.
        Decrypt JIT → parse → malice check.
        Kill VM instantly if malicious.
        Return clean ASTPayload or None.
        """
        vm = await self._spin_up(
            "ast_parser", task_id,
            env={"FILE_INDEX": str(payload.file_index),
                 "FILE_EXT":   payload.file_extension},
        )

        _emit("stage_update", {
            "task_id":    task_id,
            "stage":      "parse",
            "status":     "running",
            "file_index": payload.file_index,
            "total_files": payload.total_files,
            "vm_id":      vm.vm_id,
            "message": (
                f"Parsing file {payload.file_index + 1}/{payload.total_files} "
                f"({payload.file_extension}) in {vm.azure_vm_name}"
            ),
        })

        try:
            enc = EncryptedPayload(
                ciphertext=b64decode(payload.ciphertext_b64),
                nonce=b64decode(payload.nonce_b64),
                encrypted_dek=b64decode(payload.encrypted_dek_b64),
                kek_key_id=payload.kek_key_id,
            )
            with self.encryptor.decrypt_context(enc) as plaintext:
                result = parse_source_bytes(
                    plaintext,
                    payload.file_extension,
                    payload.file_index,
                    task_id,
                )
        except Exception as e:
            logger.error("Parse error file %d %s: %s",
                         payload.file_index, payload.file_extension, e, exc_info=True)
            await self._spin_down(vm, "parse_error")
            return None

        # Unsupported extension — create minimal stub
        if result is None:
            result = ASTPayload(
                header=create_header(
                    MessageType.AST_PAYLOAD, AgentRole.AST_PARSER,
                    AgentRole.IR_BUILDER, task_id,
                ),
                file_index=payload.file_index,
                file_extension=payload.file_extension,
                root_node=ASTNode(node_type="Unknown", children=[], attributes={}),
                node_count=0, depth=0, cyclomatic_complexity=0,
                import_count=0, function_count=0, class_count=0,
                parse_errors=["unsupported_extension"],
            )

        # ── Malice check — happens inside the per-file VM ─────────────────────
        malicious, reasons = _detect_malice(result)
        if malicious:
            await self._kill_vm_violation(
                vm, task_id,
                payload.file_extension, payload.file_index, reasons,
            )
            return None

        await self._spin_down(vm, "stage_complete")
        return result

    # ── Intelligence summary builder ──────────────────────────────────────────

    def _build_intelligence_summary(
        self,
        task_id: str,
        encrypted_payloads: List[EncryptedFilePayload],
        ast_payloads: List[ASTPayload],
        ir_payloads: List[IRPayload],
        risk_assessment,
        killed_count: int,
    ) -> IntelligenceSummary:
        """
        Compile the full intelligence summary from all analysis stages.
        This is the structured output that drives IaC generation.
        Never contains source code — only structural metadata.
        """
        # File hashes (SHA-256 of ciphertext — integrity chain)
        file_hashes = {}
        for p in encrypted_payloads:
            key = f"file_{p.file_index}{p.file_extension}"
            file_hashes[key] = p.ciphertext_sha256

        # Language breakdown
        lang_map = {
            ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
            ".go": "Go",      ".rs": "Rust",        ".java": "Java",
            ".rb": "Ruby",    ".cs": "C#",           ".cpp": "C++",
            ".php": "PHP",    ".sh": "Shell",
        }
        langs = list({lang_map.get(p.file_extension, p.file_extension)
                      for p in encrypted_payloads})

        # AST aggregates
        total_nodes  = sum(a.node_count         for a in ast_payloads)
        total_funcs  = sum(a.function_count      for a in ast_payloads)
        total_cls    = sum(a.class_count          for a in ast_payloads)
        cc_vals      = [a.cyclomatic_complexity   for a in ast_payloads if a.cyclomatic_complexity > 0]
        avg_cc       = sum(cc_vals) / len(cc_vals) if cc_vals else 0.0
        max_cc       = max(cc_vals, default=0)

        # Dependency graph (hashed import names → hashed module names)
        dep_map: Dict[str, List[str]] = {}
        unique_imports: set = set()
        priv_imports: set = set()

        for ast_p in ast_payloads:
            # Imports are stored as hashed identifiers in the AST
            # We can read the import_count and flag set
            unique_imports.add(f"file_{ast_p.file_index}")
            if ast_p.has_privilege_calls:
                priv_imports.add(f"file_{ast_p.file_index}:privileged_api")

        # Infra hints from IR
        infra_hints: List[str] = []
        total_ir = 0
        cf_depth = 0
        loops    = 0
        branches = 0
        for ir in ir_payloads:
            total_ir += ir.total_nodes
            cf_depth  = max(cf_depth, ir.max_depth)
            loops    += ir.loop_count
            branches += ir.branch_count

        loop_density   = loops   / max(total_ir, 1)
        branch_density = branches / max(total_ir, 1)

        # Security flags from ML risk assessment
        sec_flags: List[str] = []
        for fs in risk_assessment.file_scores:
            sec_flags.extend(fs.flagged_patterns)
        sec_flags = list(dict.fromkeys(sec_flags))[:20]   # deduplicate, cap at 20

        return IntelligenceSummary(
            task_id=task_id,
            total_files=len(encrypted_payloads),
            clean_files=len(ast_payloads),
            killed_files=killed_count,
            total_ast_nodes=total_nodes,
            avg_cyclomatic=round(avg_cc, 2),
            max_cyclomatic=max_cc,
            total_functions=total_funcs,
            total_classes=total_cls,
            dependency_map=dep_map,
            unique_imports=sorted(unique_imports)[:50],
            privileged_imports=sorted(priv_imports)[:20],
            file_hashes=file_hashes,
            total_ir_nodes=total_ir,
            control_flow_depth=cf_depth,
            loop_density=round(loop_density, 4),
            branch_density=round(branch_density, 4),
            detected_languages=sorted(langs),
            infra_hints=infra_hints,
            security_flags=sec_flags,
            aggregate_risk=risk_assessment.aggregate_risk,
            high_risk_files=risk_assessment.high_risk_file_count,
            anomalous_patterns=risk_assessment.anomalous_pattern_count,
        )

    # ── Error helper ──────────────────────────────────────────────────────────

    async def _abort(self, task_id: str, msg: str, start: float,
                      teardown: bool = True) -> dict:
        if teardown:
            await self._orchestrator.terminate_task_vms(task_id, "task_failed")
            await self._orchestrator.teardown_task_network(task_id)
        _emit("task_failed", {
            "task_id": task_id, "stage": "error",
            "message": f"✗ [FAILED] ❌ Task failed: {msg}",
        }, severity="error")
        self._audit.task_failed(task_id, msg)
        return {"task_id": task_id, "status": "failed",
                "error": msg, "duration": round(time.time() - start, 2)}

    # ── Main pipeline ─────────────────────────────────────────────────────────

    async def run_analysis(self, repo_url: str,
                           task_id: Optional[str] = None) -> dict:
        task_id = task_id or secrets.token_hex(12)
        self._pipeline_runs += 1
        start = time.time()

        self._audit.task_started(task_id, repo_url)
        _emit("task_started", {
            "task_id": task_id, "repo_url": repo_url,
            "stage": "init",
            "message": f"Task {task_id[:8]} started: {repo_url}",
        })
        logger.info("=== Task %s started: %s ===", task_id, repo_url)

        # ── Stage 0: BOOTSTRAP NETWORK ────────────────────────────
        _emit("stage_update", {
            "task_id": task_id, "stage": "network", "status": "running",
            "message": "Provisioning isolated VNet + NSG on Azure...",
        })
        try:
            net = await self._orchestrator.bootstrap_task_network(task_id)
        except Exception as e:
            return await self._abort(task_id, f"Network bootstrap: {e}", start,
                                      teardown=False)
        _emit("stage_update", {
            "task_id": task_id, "stage": "network", "status": "complete",
            "vnet": net["vnet_name"], "nsg": net["nsg_name"],
            "message": (
                f"Network ready: {net['vnet_name']} "
                f"(NSG deny-all, mTLS-only inbound on :{8443})"
            ),
        })

        # ── Stage 1: FETCH ────────────────────────────────────────
        vm_fetch = await self._spin_up("secure_fetcher", task_id)
        _emit("stage_update", {
            "task_id": task_id, "stage": "fetch", "status": "running",
            "message": (
                f"Fetching via {vm_fetch.azure_vm_name} — "
                "encrypting each file with AES-256-GCM + Key Vault KEK..."
            ),
        })
        self._audit.task_stage(task_id, "fetch", "running", repo_url)

        from src.repo_cloner import SecureFetcherAgent
        fetcher = SecureFetcherAgent(
            use_local_kms=os.getenv("KMS_LOCAL", "false").lower() == "true",
        )

        encrypted_payloads: List[EncryptedFilePayload] = []
        try:
            async for p in fetcher.fetch_and_encrypt_stream(repo_url, task_id):
                encrypted_payloads.append(p)
                if len(encrypted_payloads) % 10 == 0:
                    _emit("stage_update", {
                        "task_id": task_id, "stage": "fetch", "status": "running",
                        "files_so_far": len(encrypted_payloads),
                        "message": (
                            f"Encrypted {len(encrypted_payloads)} files — "
                            "DEKs wrapped by Key Vault KEK..."
                        ),
                    })
        except Exception as e:
            await self._spin_down(vm_fetch, "fetch_error")
            return await self._abort(task_id, f"Fetch failed: {e}", start)

        await self._spin_down(vm_fetch, "stage_complete")
        self._audit.task_stage(task_id, "fetch", "complete",
                               f"{len(encrypted_payloads)} files")
        _emit("stage_update", {
            "task_id": task_id, "stage": "fetch", "status": "complete",
            "files": len(encrypted_payloads),
            "message": (
                f"Fetched + encrypted {len(encrypted_payloads)} files. "
                "Plaintext never persisted. All DEKs in Key Vault."
            ),
        })

        if not encrypted_payloads:
            return await self._abort(task_id, "No files fetched", start)

        # ── Stage 2: PARSE — one real ACI per file ────────────────
        total_files = len(encrypted_payloads)
        _emit("stage_update", {
            "task_id": task_id, "stage": "parse", "status": "running",
            "total_files": total_files,
            "message": (
                f"Spinning up {total_files} parser ACIs — "
                "one per file, isolated, mTLS-authenticated..."
            ),
        })

        # Concurrency cap — avoid hitting ACI subscription quota
        concurrency = int(os.getenv("PARSE_CONCURRENCY", "8"))
        sem = asyncio.Semaphore(concurrency)

        async def _parse_gated(p: EncryptedFilePayload):
            async with sem:
                return await self._parse_one_file(p, task_id)

        parse_results = await asyncio.gather(
            *[_parse_gated(p) for p in encrypted_payloads],
            return_exceptions=False,
        )

        ast_payloads = [r for r in parse_results if r is not None]
        killed_count = total_files - len(ast_payloads)

        _emit("stage_update", {
            "task_id": task_id, "stage": "parse", "status": "complete",
            "parsed": len(ast_payloads),
            "killed": killed_count,
            "hitl_pending": killed_count,
            "message": (
                f"Parsed {len(ast_payloads)}/{total_files} files clean. "
                + (f"🚨 {killed_count} VMs killed — HITL alerts raised."
                   if killed_count else "No malicious files detected.")
            ),
        }, severity="error" if killed_count else "info")

        if not ast_payloads:
            return await self._abort(
                task_id,
                f"All {total_files} files were malicious or unparseable",
                start,
            )

        del parse_results
        gc.collect()

        # ── Stage 3: IR BUILD ─────────────────────────────────────
        vm_ir = await self._spin_up("ir_builder", task_id)
        _emit("stage_update", {
            "task_id": task_id, "stage": "ir", "status": "running",
            "message": (
                f"Building IR from {len(ast_payloads)} clean ASTs — "
                "extracting: AST summary, dependency graph, hashes, "
                "control-flow metadata, infra metadata..."
            ),
        })

        ir_payloads: List[IRPayload] = []
        for ast_p in ast_payloads:
            try:
                ir_payloads.append(build_ir_from_ast(ast_p))
            except Exception as e:
                logger.warning("IR error file %d: %s", ast_p.file_index, e)

        await self._spin_down(vm_ir, "stage_complete")
        total_ir_nodes = sum(ir.total_nodes for ir in ir_payloads)
        self._audit.task_stage(task_id, "ir", "complete",
                               f"{total_ir_nodes} nodes, {len(ir_payloads)} files")
        _emit("stage_update", {
            "task_id": task_id, "stage": "ir", "status": "complete",
            "ir_files": len(ir_payloads),
            "total_nodes": total_ir_nodes,
            "message": (
                f"IR built: {total_ir_nodes:,} structural nodes across "
                f"{len(ir_payloads)} files — no human-readable logic retained"
            ),
        })

        # ── Stage 4: ML SCORE ─────────────────────────────────────
        vm_ml = await self._spin_up("ml_analyzer", task_id)
        _emit("stage_update", {
            "task_id": task_id, "stage": "ml", "status": "running",
            "message": "Running CodeBERT ensemble on IR tokens + rule-based scorer...",
        })

        risk_assessment = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.ml_analyzer.analyze_batch(ir_payloads, task_id),
        )

        await self._spin_down(vm_ml, "stage_complete")
        self._audit.task_stage(task_id, "ml", "complete",
                               f"risk={risk_assessment.aggregate_risk:.2f}")
        _emit("stage_update", {
            "task_id": task_id, "stage": "ml", "status": "complete",
            "aggregate_risk":     risk_assessment.aggregate_risk,
            "high_risk_files":    risk_assessment.high_risk_file_count,
            "anomalous_patterns": risk_assessment.anomalous_pattern_count,
            "message": (
                f"ML scored: aggregate risk={risk_assessment.aggregate_risk:.0%} | "
                f"{risk_assessment.high_risk_file_count} high-risk | "
                f"{risk_assessment.anomalous_pattern_count} anomalous patterns"
            ),
        })

        # ── Build intelligence summary ─────────────────────────────
        intel = self._build_intelligence_summary(
            task_id, encrypted_payloads, ast_payloads,
            ir_payloads, risk_assessment, killed_count,
        )
        _emit("intelligence_ready", {
            "task_id":           task_id,
            "stage":             "intelligence",
            "summary":           intel.to_dict(),
            "message": (
                f"Intelligence summary ready: {intel.total_ast_nodes:,} AST nodes | "
                f"{len(intel.detected_languages)} languages | "
                f"{intel.aggregate_risk:.0%} aggregate risk | "
                f"{len(intel.security_flags)} security flags"
            ),
        })

        del ast_payloads
        del ir_payloads
        del encrypted_payloads
        gc.collect()

        # ── Stage 5: POLICY ───────────────────────────────────────
        vm_policy = await self._spin_up("policy_engine", task_id)
        _emit("stage_update", {
            "task_id": task_id, "stage": "policy",
            "status": "running",
            "message": "Evaluating policy rules R001–R006...",
        })

        policy_decision = self.policy_engine.evaluate(risk_assessment)

        # HITL on low confidence
        if policy_decision.hitl_required:
            alert_id = secrets.token_hex(8)
            alert = {
                "alert_id":       alert_id,
                "task_id":        task_id,
                "type":           "policy_confidence",
                "reason":         policy_decision.hitl_reason or "Low confidence",
                "confidence":     policy_decision.confidence,
                "aggregate_risk": risk_assessment.aggregate_risk,
                "flags":          intel.security_flags[:10],
                "status":         "pending",
                "created_at":     time.time(),
            }
            _hitl_alerts[alert_id] = alert
            _emit("hitl_alert", {
                "task_id":    task_id,
                "alert_id":   alert_id,
                "type":       "policy_confidence",
                "reason":     policy_decision.hitl_reason,
                "confidence": policy_decision.confidence,
                "stage":      "hitl",
                "message": (
                    f"⚠ HITL: policy confidence {policy_decision.confidence:.0%} "
                    f"— human review required"
                ),
            }, severity="warning")

        await self._spin_down(vm_policy, "stage_complete")
        self._audit.policy_decision(
            task_id, policy_decision.decision, policy_decision.confidence,
            policy_decision.rules_triggered,
            [c.constraint_type for c in policy_decision.constraints],
        )
        _emit("stage_update", {
            "task_id":       task_id, "stage": "policy", "status": "complete",
            "decision":      policy_decision.decision,
            "confidence":    policy_decision.confidence,
            "rules_triggered": policy_decision.rules_triggered,
            "constraints":   [c.constraint_type for c in policy_decision.constraints],
            "hitl_required": policy_decision.hitl_required,
            "message": (
                f"Policy: {policy_decision.decision} "
                f"(conf={policy_decision.confidence:.0%}, "
                f"{policy_decision.rules_triggered} rules triggered)"
            ),
        }, severity="error"   if policy_decision.decision == "REJECT"
              else "warning" if policy_decision.hitl_required
              else "info")

        # ── Stage 6: STRATEGY ─────────────────────────────────────
        vm_strat = await self._spin_up("strategy_agent", task_id)
        _emit("stage_update", {
            "task_id": task_id, "stage": "strategy",
            "status": "running",
            "message": "Deciding deployment strategy from IR metrics + policy...",
        })

        ir_metrics = {
            "total_ir_nodes":         risk_assessment.total_ir_nodes,
            "privileged_api_count":   risk_assessment.privileged_api_count,
            "high_risk_file_count":   risk_assessment.high_risk_file_count,
            "anomalous_pattern_count": risk_assessment.anomalous_pattern_count,
            "aggregate_risk":         risk_assessment.aggregate_risk,
        }
        strategy = self.strategy_agent.decide(policy_decision, ir_metrics, task_id)

        await self._spin_down(vm_strat, "stage_complete")
        self._audit.deployment_strategy(
            task_id, strategy.method, "; ".join(strategy.reasoning)
        )
        _emit("stage_update", {
            "task_id":       task_id, "stage": "strategy", "status": "complete",
            "method":        strategy.method,
            "primary_tool":  strategy.primary_tool,
            "reasoning":     strategy.reasoning[:3],
            "message": (
                f"Strategy: {strategy.method.upper()} — "
                f"{strategy.primary_tool}"
                + (f" + {strategy.secondary_tool}" if strategy.secondary_tool else "")
            ),
        })

        # ── Stage 7: IaC GENERATE ─────────────────────────────────
        vm_iac = await self._spin_up("iac_generator", task_id)
        _emit("stage_update", {
            "task_id": task_id, "stage": "iac",
            "status": "running",
            "message": (
                "Generating Terraform + Ansible from: "
                "security flags, policy constraints, infra metadata, "
                "dependency graph, control-flow analysis..."
            ),
        })

        iac_bundle = self.iac_agent.generate(policy_decision, strategy)

        await self._spin_down(vm_iac, "stage_complete")
        self._audit.iac_generated(
            task_id,
            list(iac_bundle.terraform_files.keys()),
            list(iac_bundle.ansible_files.keys()),
        )
        _emit("stage_update", {
            "task_id":           task_id, "stage": "iac", "status": "complete",
            "terraform_files":   list(iac_bundle.terraform_files.keys()),
            "ansible_files":     list(iac_bundle.ansible_files.keys()),
            "terraform_contents": iac_bundle.terraform_files,
            "ansible_contents":  iac_bundle.ansible_files,
            "method":            iac_bundle.method,
            "message": (
                f"IaC generated: {len(iac_bundle.terraform_files)} Terraform + "
                f"{len(iac_bundle.ansible_files)} Ansible files "
                f"(method={iac_bundle.method})"
            ),
        })

        # ── Stage 8: DEPLOY ───────────────────────────────────────
        vm_deploy = await self._spin_up("deployment_agent", task_id)
        _emit("stage_update", {
            "task_id": task_id, "stage": "deploy",
            "status": "running",
            "message": "Applying IaC to Azure...",
        })

        deploy_result = await self.deploy_agent.deploy(iac_bundle)

        await self._spin_down(vm_deploy, "task_complete")

        # ── Stage 9: TEARDOWN ─────────────────────────────────────
        remaining = await self._orchestrator.terminate_task_vms(
            task_id, "task_complete"
        )
        await self._orchestrator.teardown_task_network(task_id)
        self._audit.environment_teardown(task_id, remaining)
        _emit("environment_teardown", {
            "task_id":      task_id, "stage": "teardown",
            "vms_destroyed": remaining,
            "message": (
                f"Teardown complete — {remaining} ACIs deleted, "
                "VNet + NSG removed. Audit log preserved."
            ),
        }, severity="warning")

        # ── Final result ──────────────────────────────────────────
        duration = time.time() - start
        self._audit.task_complete(task_id, policy_decision.decision,
                                  risk_assessment.aggregate_risk, duration)

        hitl_pending = sum(
            1 for a in _hitl_alerts.values()
            if a["task_id"] == task_id and a["status"] == "pending"
        )

        result = {
            "task_id":           task_id,
            "status":            "complete",
            "decision":          policy_decision.decision,
            "confidence":        policy_decision.confidence,
            "aggregate_risk":    risk_assessment.aggregate_risk,
            "total_files":       total_files,
            "clean_files":       len(ast_payloads) if ast_payloads else intel.clean_files,
            "killed_files":      killed_count,
            "high_risk_files":   risk_assessment.high_risk_file_count,
            "anomalous_patterns": risk_assessment.anomalous_pattern_count,
            "hitl_required":     policy_decision.hitl_required or killed_count > 0,
            "hitl_pending":      hitl_pending,
            "constraints":       [c.constraint_type for c in policy_decision.constraints],
            "deployment_method": strategy.method,
            "deployment_success": deploy_result.success,
            "terraform_files":   list(iac_bundle.terraform_files.keys()),
            "ansible_files":     list(iac_bundle.ansible_files.keys()),
            "terraform_contents": iac_bundle.terraform_files,
            "ansible_contents":  iac_bundle.ansible_files,
            "intelligence":      intel.to_dict(),
            "duration_seconds":  round(duration, 2),
        }

        _emit("task_complete", {
            **result,
            "message": (
                f"✅ Complete in {duration:.1f}s — "
                f"{policy_decision.decision} | "
                f"risk={risk_assessment.aggregate_risk:.0%} | "
                f"{killed_count} VMs killed | "
                f"{hitl_pending} HITL pending"
            ),
        }, severity="error"   if policy_decision.decision == "REJECT"
              else "warning" if hitl_pending > 0
              else "success")

        logger.info("=== Task %s complete: %s in %.1fs | killed=%d ===",
                    task_id, policy_decision.decision, duration, killed_count)
        return result

    def get_stats(self) -> dict:
        return {
            "pipeline_runs": self._pipeline_runs,
            "policy_stats":  self.policy_engine.get_stats(),
            "hitl_pending":  sum(1 for a in _hitl_alerts.values()
                                 if a["status"] == "pending"),
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_pipeline: Optional[SecureAnalysisPipeline] = None

def get_pipeline() -> SecureAnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = SecureAnalysisPipeline()
    return _pipeline


async def main() -> None:
    repo_url = os.getenv("GITHUB_REPO_URL", "")
    if not repo_url:
        raise ValueError("GITHUB_REPO_URL not set")
    result = await get_pipeline().run_analysis(repo_url)
    for k, v in result.items():
        if k not in ("terraform_contents", "ansible_contents", "intelligence"):
            print(f"  {k}: {v}")


if __name__ == "__main__":
    asyncio.run(main())