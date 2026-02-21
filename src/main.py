"""
Pipeline Orchestrator — main.py

Full workflow for one GitHub repository:

  Stage 1 — FETCH       : SecureFetcherAgent pulls files, encrypts each immediately
  Stage 2 — PARSE       : AST Parser decrypts JIT, strips semantics, emits ASTPayload
  Stage 3 — IR BUILD    : IR Builder converts sanitised AST → language-agnostic IR
  Stage 4 — ML SCORE    : MLSecurityAnalyzer scores IR with CodeBERT + rules
  Stage 5 — POLICY      : PolicyEngine evaluates RiskAssessment → APPROVE/REJECT/+CONSTRAINTS
  Stage 6 — STRATEGY    : DeploymentStrategyAgent decides declarative / imperative / hybrid
  Stage 7 — IaC GEN     : IaCGeneratorAgent produces Terraform + Ansible bundle
  Stage 8 — DEPLOY      : DeploymentAgent applies IaC in ephemeral VM, then teardown

After Stage 8: all microVMs are destroyed. Audit log is kept forever.
"""
from __future__ import annotations

import asyncio
import gc
import logging
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from config.azure_config import AGENT_CONFIG
from src.analyzer.ast_parser import parse_python_source
from src.analyzer.ir_builder import build_ir_from_ast
from src.analyzer.ml_analyzer import MLSecurityAnalyzer
from src.agents.policy_engine import PolicyEngine
from src.agents.deployment_strategy import DeploymentStrategyAgent
from src.agents.iac_generator import IaCGeneratorAgent
from src.agents.deployment_agent import DeploymentAgent
from src.key_management import FileEncryptor, build_kms
from src.schemas.a2a_schemas import (
    AgentRole, ASTPayload, EncryptedFilePayload, IRPayload,
    MessageType, PolicyDecision, RiskAssessment,
    TaskManifest, ViolationEvent, create_header,
)
from src.security.mtls import MTLSConfig
from logs.audit import get_audit

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

for lib in ("azure", "urllib3", "transformers", "torch"):
    logging.getLogger(lib).setLevel(logging.WARNING)


# ── UI event bridge (set by ui/monitor.py at startup) ────────────
_ui_event_callback = None


def set_ui_callback(fn) -> None:
    global _ui_event_callback
    _ui_event_callback = fn


def _emit(event_type: str, data: dict, severity: str = "info") -> None:
    """Emit an event to both the audit log and the UI."""
    get_audit().log(event_type, severity, task_id=data.get("task_id"),
                    stage=data.get("stage"), message=data.get("message", ""),
                    data={k: v for k, v in data.items()
                          if k not in ("task_id", "stage", "message")})
    if _ui_event_callback:
        try:
            _ui_event_callback(event_type, data, severity)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────
# MicroVM registry (lightweight, in-process representation)
# ─────────────────────────────────────────────────────────────────

class VMRegistry:
    """Tracks which VMs exist for a task. Notifies UI on create/destroy."""

    def __init__(self, task_id: str) -> None:
        self._task_id = task_id
        self._vms: Dict[str, dict] = {}
        self._audit = get_audit()

    def create(self, role: str) -> str:
        vm_id = secrets.token_hex(6)
        last_octet = (hash(vm_id) % 254) + 1
        ip = f"10.0.1.{last_octet}"
        record = {
            "vm_id": vm_id,
            "role": role,
            "task_id": self._task_id,
            "status": "running",
            "private_ip": ip,
            "azure_vm_name": f"agent-{role[:10]}-{vm_id}",
            "created_at": time.time(),
            "age_seconds": 0,
        }
        self._vms[vm_id] = record
        self._audit.vm_created(self._task_id, vm_id, role, ip)
        _emit("vm_created", {**record, "task_id": self._task_id,
                              "message": f"µVM created: {role}"})
        logger.info("µVM created: role=%s id=%s ip=%s", role, vm_id, ip)
        return vm_id

    def destroy(self, vm_id: str, reason: str = "task_complete") -> None:
        if vm_id not in self._vms:
            return
        rec = self._vms[vm_id]
        rec["status"] = "terminated"
        rec["terminated_at"] = time.time()
        self._audit.vm_destroyed(self._task_id, vm_id, rec["role"], reason)
        _emit("vm_terminated", {"vm_id": vm_id, "role": rec["role"],
                                 "task_id": self._task_id,
                                 "reason": reason, "stage": "vm_lifecycle",
                                 "message": f"µVM destroyed: {rec['role']} ({reason})"})
        logger.info("µVM destroyed: role=%s id=%s reason=%s", rec["role"], vm_id, reason)

    def destroy_all(self, reason: str = "task_complete") -> int:
        ids = list(self._vms.keys())
        for vm_id in ids:
            if self._vms[vm_id].get("status") == "running":
                self.destroy(vm_id, reason)
        return len(ids)

    def list_active(self) -> List[dict]:
        return [v for v in self._vms.values() if v["status"] == "running"]


# ─────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────

class SecureAnalysisPipeline:
    """
    Coordinates all 8 stages.
    """

    def __init__(self, use_local_kms: bool = None) -> None:
        # Respect KMS_LOCAL env var; default False for Azure deployments
        if use_local_kms is None:
            use_local_kms = os.getenv("KMS_LOCAL", "false").lower() == "true"
        self.kms = build_kms(use_local=use_local_kms)
        self.encryptor = FileEncryptor(self.kms)
        self.ml_analyzer = MLSecurityAnalyzer()
        self.policy_engine = PolicyEngine()
        self.strategy_agent = DeploymentStrategyAgent()
        self.iac_agent = IaCGeneratorAgent()
        self.deploy_agent = DeploymentAgent()
        self._audit = get_audit()
        self._pipeline_runs = 0

    # ── Stage 2 helper ───────────────────────────────────────────

    def _decrypt_and_parse(self, payload: EncryptedFilePayload) -> Optional[ASTPayload]:
        """Decrypt → parse → return ASTPayload. Plaintext lives only inside this call."""
        from base64 import b64decode
        from src.key_management import EncryptedPayload
        from src.parser import parse_source_bytes

        try:
            enc = EncryptedPayload(
                ciphertext=b64decode(payload.ciphertext_b64),
                nonce=b64decode(payload.nonce_b64),
                encrypted_dek=b64decode(payload.encrypted_dek_b64),
                kek_key_id=payload.kek_key_id,
            )
            with self.encryptor.decrypt_context(enc) as plaintext_bytes:
                ext = payload.file_extension
                result = parse_source_bytes(
                    plaintext_bytes, ext,
                    payload.file_index, payload.header.task_id,
                )
                if result is None:
                    from src.schemas.a2a_schemas import ASTNode, create_header
                    result = ASTPayload(
                        header=create_header(MessageType.AST_PAYLOAD,
                                             AgentRole.AST_PARSER,
                                             AgentRole.IR_BUILDER,
                                             payload.header.task_id),
                        file_index=payload.file_index,
                        file_extension=ext,
                        root_node=ASTNode(node_type="Module", children=[], attributes={}),
                        node_count=0, depth=0, cyclomatic_complexity=0,
                        import_count=0, function_count=0, class_count=0,
                        parse_errors=["unsupported_extension"],
                    )
            return result
        except Exception as e:
            logger.error("Parse error file %d ext=%s: %s: %s",
                         payload.file_index, payload.file_extension,
                         type(e).__name__, e, exc_info=True)
            return None

    # ── Main run ─────────────────────────────────────────────────

    async def run_analysis(self, repo_url: str, task_id: Optional[str] = None) -> dict:
        task_id = task_id or secrets.token_hex(12)
        self._pipeline_runs += 1
        vms = VMRegistry(task_id)
        start = time.time()

        self._audit.task_started(task_id, repo_url)
        _emit("task_started", {"task_id": task_id, "repo_url": repo_url,
                                "stage": "init", "message": f"Task started: {repo_url}"})
        logger.info("=== Task %s started: %s ===", task_id, repo_url)

        # ── Stage 1: FETCH ────────────────────────────────────────
        vm_fetch = vms.create("secure_fetcher")
        _emit("stage_update", {"task_id": task_id, "stage": "fetch",
                                "status": "running", "message": "Fetching repository files..."})
        self._audit.task_stage(task_id, "fetch", "running", repo_url)

        from src.repo_cloner import SecureFetcherAgent

        # FIX: use OS-agnostic temp dir (works on Windows, Linux, macOS)
        _tmp = tempfile.gettempdir()
        _cert_path = os.getenv("MTLS_CERT_PATH", os.path.join(_tmp, "agent.crt"))
        _key_path  = os.getenv("MTLS_KEY_PATH",  os.path.join(_tmp, "agent.key"))
        _ca_path   = os.getenv("MTLS_CA_PATH",   os.path.join(_tmp, "ca.crt"))

        if not (Path(_cert_path).exists() and Path(_key_path).exists() and Path(_ca_path).exists()):
            from src.security.mtls import generate_ca_certificate, generate_agent_certificate
            ca_cert_pem, ca_key_pem = generate_ca_certificate()
            agent_cert_pem, agent_key_pem = generate_agent_certificate(
                agent_id=f"fetcher-{task_id[:8]}",
                ca_cert_pem=ca_cert_pem,
                ca_key_pem=ca_key_pem,
                validity_hours=2,
            )
            Path(_cert_path).write_bytes(agent_cert_pem)
            Path(_key_path).write_bytes(agent_key_pem)
            Path(_ca_path).write_bytes(ca_cert_pem)

        mtls_cfg = MTLSConfig(
            cert_path=_cert_path,
            key_path=_key_path,
            ca_path=_ca_path,
            agent_id=f"fetcher-{task_id[:8]}",
        )
        fetcher = SecureFetcherAgent(mtls_config=mtls_cfg, parser_host="localhost",
                                     parser_port=8443,
                                     use_local_kms=os.getenv("KMS_LOCAL", "false").lower() == "true")
        encrypted_payloads: List[EncryptedFilePayload] = []

        try:
            async for p in fetcher.fetch_and_encrypt_stream(repo_url, task_id):
                encrypted_payloads.append(p)
        except Exception as e:
            logger.exception("Fetch stage failed:")
            vms.destroy(vm_fetch, "fetch_error")
            vms.destroy_all("task_failed")
            self._audit.task_failed(task_id, str(e))
            return self._error(task_id, f"Fetch failed: {type(e).__name__}: {e}", start)

        vms.destroy(vm_fetch, "stage_complete")
        self._audit.task_stage(task_id, "fetch", "complete",
                               f"{len(encrypted_payloads)} files encrypted")
        _emit("stage_update", {"task_id": task_id, "stage": "fetch", "status": "complete",
                                "files": len(encrypted_payloads),
                                "message": f"Fetched and encrypted {len(encrypted_payloads)} files"})

        if not encrypted_payloads:
            vms.destroy_all("task_failed")
            return self._error(task_id, "No files fetched from repository", start)

        # ── Stage 2: PARSE ────────────────────────────────────────
        vm_parse = vms.create("ast_parser")
        _emit("stage_update", {"task_id": task_id, "stage": "parse",
                                "status": "running",
                                "message": f"Parsing {len(encrypted_payloads)} files..."})

        ast_payloads: List[ASTPayload] = []
        parse_errors = 0
        for ep in encrypted_payloads:
            result = self._decrypt_and_parse(ep)
            if result:
                ast_payloads.append(result)
            else:
                parse_errors += 1

        del encrypted_payloads
        gc.collect()

        vms.destroy(vm_parse, "stage_complete")
        self._audit.task_stage(task_id, "parse", "complete",
                               f"{len(ast_payloads)} parsed, {parse_errors} errors")
        _emit("stage_update", {
            "task_id": task_id, "stage": "parse", "status": "complete",
            "parsed": len(ast_payloads), "errors": parse_errors,
            "message": f"Parsed {len(ast_payloads)} files ({parse_errors} errors)",
        })

        if not ast_payloads:
            vms.destroy_all("task_failed")
            return self._error(task_id, "All files failed to parse", start)

        # ── Stage 3: IR BUILD ─────────────────────────────────────
        vm_ir = vms.create("ir_builder")
        _emit("stage_update", {"task_id": task_id, "stage": "ir",
                                "status": "running", "message": "Building IR..."})

        ir_payloads: List[IRPayload] = []
        for ap in ast_payloads:
            try:
                ir = build_ir_from_ast(ap)
                ir_payloads.append(ir)
            except Exception as e:
                logger.warning("IR build error file %d: %s", ap.file_index, e)

        del ast_payloads
        gc.collect()

        total_nodes = sum(ir.total_nodes for ir in ir_payloads)
        vms.destroy(vm_ir, "stage_complete")
        self._audit.task_stage(task_id, "ir", "complete",
                               f"{len(ir_payloads)} IR payloads, {total_nodes} nodes")
        _emit("stage_update", {
            "task_id": task_id, "stage": "ir", "status": "complete",
            "ir_count": len(ir_payloads), "total_nodes": total_nodes,
            "message": f"IR built: {total_nodes} structural nodes across {len(ir_payloads)} files",
        })

        # ── Stage 4: ML SCORE ─────────────────────────────────────
        vm_ml = vms.create("ml_analyzer")
        _emit("stage_update", {"task_id": task_id, "stage": "ml",
                                "status": "running", "message": "Running ML security analysis..."})

        risk_assessment = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.ml_analyzer.analyze_batch(ir_payloads, task_id),
        )

        del ir_payloads
        gc.collect()

        vms.destroy(vm_ml, "stage_complete")
        self._audit.task_stage(task_id, "ml", "complete",
                               f"aggregate_risk={risk_assessment.aggregate_risk:.2f}")
        _emit("stage_update", {
            "task_id": task_id, "stage": "ml", "status": "complete",
            "aggregate_risk": risk_assessment.aggregate_risk,
            "high_risk_files": risk_assessment.high_risk_file_count,
            "anomalous_patterns": risk_assessment.anomalous_pattern_count,
            "message": (f"Risk scored: {risk_assessment.aggregate_risk:.0%} aggregate risk, "
                        f"{risk_assessment.high_risk_file_count} high-risk files"),
        })

        # ── Stage 5: POLICY ───────────────────────────────────────
        vm_policy = vms.create("policy_engine")
        _emit("stage_update", {"task_id": task_id, "stage": "policy",
                                "status": "running", "message": "Evaluating policy rules..."})

        policy_decision = self.policy_engine.evaluate(risk_assessment)

        # ── HITL escalation (non-blocking: emit event, continue with provisional decision) ──
        if policy_decision.hitl_required:
            hitl_req = self.policy_engine.create_hitl_request(
                risk_assessment, policy_decision.hitl_reason or "Confidence below threshold"
            )
            _emit("hitl_required", {
                "task_id": task_id,
                "stage": "policy",
                "hitl_request_id": hitl_req.header.message_id,
                "reason": hitl_req.reason,
                "aggregate_risk": hitl_req.aggregate_risk,
                "flagged_patterns": hitl_req.flagged_patterns,
                "recommended_action": hitl_req.recommended_action,
                "expires_at": hitl_req.expires_at,
                "message": f"⚠️ HITL required: {hitl_req.reason}",
            }, severity="warning")
            logger.warning("HITL escalation required for task %s: %s", task_id, hitl_req.reason)

        vms.destroy(vm_policy, "stage_complete")
        self._audit.policy_decision(
            task_id, policy_decision.decision, policy_decision.confidence,
            policy_decision.rules_triggered,
            [c.constraint_type for c in policy_decision.constraints],
        )
        _emit("stage_update", {
            "task_id": task_id, "stage": "policy", "status": "complete",
            "decision": policy_decision.decision,
            "confidence": policy_decision.confidence,
            "hitl_required": policy_decision.hitl_required,
            "constraints": [c.constraint_type for c in policy_decision.constraints],
            "message": (f"Policy: {policy_decision.decision} "
                        f"(confidence={policy_decision.confidence:.0%})"),
        })

        # ── Stage 6: STRATEGY ─────────────────────────────────────
        vm_strategy = vms.create("strategy_agent")
        _emit("stage_update", {"task_id": task_id, "stage": "strategy",
                                "status": "running", "message": "Deciding deployment strategy..."})

        ir_metrics = {
            "total_ir_nodes": risk_assessment.total_ir_nodes,
            "privileged_api_count": risk_assessment.privileged_api_count,
            "high_risk_file_count": risk_assessment.high_risk_file_count,
            "anomalous_pattern_count": risk_assessment.anomalous_pattern_count,
            "aggregate_risk": risk_assessment.aggregate_risk,
        }
        strategy = self.strategy_agent.decide(policy_decision, ir_metrics, task_id)

        vms.destroy(vm_strategy, "stage_complete")
        _emit("stage_update", {
            "task_id": task_id, "stage": "strategy", "status": "complete",
            "method": strategy.method,
            "primary_tool": strategy.primary_tool,
            "message": (f"Strategy: {strategy.method} — {strategy.primary_tool}"
                        + (f" + {strategy.secondary_tool}" if strategy.secondary_tool else "")),
        })

        # ── Stage 7: IaC GENERATE ─────────────────────────────────
        vm_iac = vms.create("iac_generator")
        _emit("stage_update", {"task_id": task_id, "stage": "iac",
                                "status": "running", "message": "Generating Terraform + Ansible..."})

        iac_bundle = self.iac_agent.generate(policy_decision, strategy)

        vms.destroy(vm_iac, "stage_complete")
        self._audit.iac_generated(
            task_id,
            list(iac_bundle.terraform_files.keys()),
            list(iac_bundle.ansible_files.keys()),
        )

        # FIX: send full file CONTENTS in the event so the UI can render + download them
        _emit("stage_update", {
            "task_id": task_id, "stage": "iac", "status": "complete",
            "terraform_files": list(iac_bundle.terraform_files.keys()),
            "ansible_files": list(iac_bundle.ansible_files.keys()),
            "terraform_contents": iac_bundle.terraform_files,   # ← full content
            "ansible_contents": iac_bundle.ansible_files,       # ← full content
            "method": iac_bundle.method,
            "message": (f"IaC generated: {len(iac_bundle.terraform_files)} Terraform + "
                        f"{len(iac_bundle.ansible_files)} Ansible files"),
        })

        # ── Stage 8: DEPLOY ───────────────────────────────────────
        vm_deploy = vms.create("deployment_agent")
        _emit("stage_update", {"task_id": task_id, "stage": "deploy",
                                "status": "running",
                                "message": "Deploying resources (ephemeral environment)..."})

        deploy_result = await self.deploy_agent.deploy(iac_bundle)

        vms.destroy(vm_deploy, "task_complete")

        # ── TEARDOWN ──────────────────────────────────────────────
        remaining = vms.destroy_all("task_complete")
        self._audit.environment_teardown(task_id, remaining)
        _emit("environment_teardown", {
            "task_id": task_id, "stage": "teardown",
            "vms_destroyed": remaining,
            "message": f"Ephemeral environment destroyed — {remaining} VMs deleted. Audit log preserved.",
        }, severity="warning")

        # ── Final result ──────────────────────────────────────────
        duration = time.time() - start
        self._audit.task_complete(task_id, policy_decision.decision,
                                  risk_assessment.aggregate_risk, duration)

        result = {
            "task_id": task_id,
            "status": "complete",
            "decision": policy_decision.decision,
            "confidence": policy_decision.confidence,
            "aggregate_risk": risk_assessment.aggregate_risk,
            "total_files": risk_assessment.total_files,
            "high_risk_files": risk_assessment.high_risk_file_count,
            "anomalous_patterns": risk_assessment.anomalous_pattern_count,
            "constraints": [c.constraint_type for c in policy_decision.constraints],
            "required_mitigations": policy_decision.required_mitigations,
            "hitl_required": policy_decision.hitl_required,
            "deployment_method": strategy.method,
            "deployment_tool": strategy.primary_tool,
            "resources_deployed": deploy_result.resources_deployed,
            "deployment_success": deploy_result.success,
            "deployment_endpoint": deploy_result.endpoint,
            "duration_seconds": duration,
            "risk_summary": policy_decision.risk_summary,
            "terraform_files": list(iac_bundle.terraform_files.keys()),
            "ansible_files": list(iac_bundle.ansible_files.keys()),
            "terraform_contents": iac_bundle.terraform_files,
            "ansible_contents": iac_bundle.ansible_files,
        }

        _emit("task_complete", {**result, "message": (
            f"Task complete in {duration:.1f}s — "
            f"{policy_decision.decision} | "
            f"risk={risk_assessment.aggregate_risk:.0%} | "
            f"deploy={strategy.method}"
        )}, severity="error" if policy_decision.decision == "REJECT"
               else "warning" if policy_decision.hitl_required else "success")

        logger.info("=== Task %s complete: %s in %.1fs ===",
                    task_id, policy_decision.decision, duration)
        return result

    @staticmethod
    def _error(task_id: str, msg: str, start: float) -> dict:
        _emit("task_failed", {"task_id": task_id, "error": msg,
                               "stage": "failed", "message": f"✗ [FAILED] ❌ Task failed: {msg}"},
              severity="error")
        return {
            "task_id": task_id, "status": "failed",
            "error": msg, "duration_seconds": time.time() - start,
        }

    def get_stats(self) -> dict:
        return {
            "pipeline_runs": self._pipeline_runs,
            "policy_stats": self.policy_engine.get_stats(),
        }


# ── Singleton ────────────────────────────────────────────────────

_pipeline: Optional[SecureAnalysisPipeline] = None


def get_pipeline() -> SecureAnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = SecureAnalysisPipeline()
    return _pipeline


async def main() -> None:
    repo_url = os.getenv("GITHUB_REPO_URL", "")
    if not repo_url:
        raise ValueError("GITHUB_REPO_URL environment variable required")
    result = await get_pipeline().run_analysis(repo_url)
    print("\n" + "=" * 60)
    for k, v in result.items():
        if k not in ("risk_summary", "terraform_contents", "ansible_contents"):
            print(f"  {k}: {v}")
    print("\nRisk Summary:\n", result.get("risk_summary", "N/A"))
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())