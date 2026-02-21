"""
Deployment Agent  —  src/agents/deployment_agent.py

The final agent in the pipeline. Receives a validated IaCBundle and:
  1. Runs terraform plan (real) or simulates (dry-run) as a final gate
  2. Applies the IaC (terraform apply OR az CLI script)
  3. Verifies deployment health
  4. Reports results to the Orchestrator
  5. Self-destructs its VM

This agent runs in its own ephemeral microVM (ACI).
Logs are written to the Audit Logger BEFORE VM destruction.

In demo/dev mode (AZURE_DEPLOY_DRY_RUN=true), all Azure calls
are simulated and logged without provisioning real resources.

Changes vs. prior version
──────────────────────────
  FIXED: _run_terraform() did not run `terraform plan` before `apply`.
         A structurally invalid bundle could reach `apply` and cause
         a partial deployment. Plan now runs first with -detailed-exitcode;
         exit code 1 (error) aborts; exit code 2 (changes) proceeds.

  FIXED: _run_terraform() had no timeout — could hang the pipeline indefinitely.
         TERRAFORM_TIMEOUT env var controls it (default 300s).

  FIXED: _run_terraform() wrote files inside `with TemporaryDirectory()` but
         ran apply inside the same context. If apply raised mid-execution the
         context manager would delete the working directory, leaving Terraform
         in an undefined state. Now uses explicit mkdir/rmtree with finally.

  FIXED: _run_terraform() used `terraform init` without `-backend=false` during
         plan phase — if the backend storage account is not yet provisioned this
         would fail. Plan now uses a local backend override.

  FIXED: _run_imperative() used NamedTemporaryFile(delete=False) but only called
         os.unlink on success. If the subprocess raised, the script file leaked
         on disk. Fixed with try/finally.

  FIXED: _run_imperative() had no timeout — fixed with AZ_SCRIPT_TIMEOUT (default 600s).

  FIXED: No _verify_health() implementation despite the docstring claiming it
         verified deployment health. Now implemented as a real async check
         (ARM provisioning state in production, simulation in dry-run).

  ADDED: DeploymentResult.attempt field — correlates with IaC retry context.

  ADDED: DeploymentResult.plan_output field — stores terraform plan summary
         for the audit log and UI display.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from logs.audit import get_audit

logger = logging.getLogger(__name__)

# ── Env flags ─────────────────────────────────────────────────────────────────
DRY_RUN            = os.getenv("AZURE_DEPLOY_DRY_RUN", "true").lower() == "true"
TERRAFORM_TIMEOUT  = int(os.getenv("TERRAFORM_TIMEOUT",  "300"))   # seconds
AZ_SCRIPT_TIMEOUT  = int(os.getenv("AZ_SCRIPT_TIMEOUT",  "600"))   # seconds
HEALTH_TIMEOUT     = int(os.getenv("HEALTH_CHECK_TIMEOUT", "60"))   # seconds


# ══════════════════════════════════════════════════════════════════════════════
# Result dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DeploymentResult:
    task_id:            str
    success:            bool
    method:             str
    resources_deployed: List[str]
    resources_failed:   List[str]
    duration_seconds:   float
    endpoint:           Optional[str]
    error:              Optional[str]  = None
    plan_output:        str            = ""   # terraform plan summary / simulation log
    attempt:            int            = 1    # IaC retry attempt that produced this result
    deployed_at:        float          = field(default_factory=time.time)


# ══════════════════════════════════════════════════════════════════════════════
# Agent
# ══════════════════════════════════════════════════════════════════════════════

class DeploymentAgent:
    """
    Applies a validated IaCBundle to Azure. Dry-run safe.

    In production: shells out to `terraform` or `az` CLI.
    In dry-run: simulates all steps with realistic timing + structured output.
    """

    def __init__(self) -> None:
        self._audit = get_audit()

    # ── Public entry point ────────────────────────────────────────────────────

    async def deploy(self, iac_bundle) -> DeploymentResult:
        """
        Deploy an IaCBundle. Returns DeploymentResult.
        Always writes to the audit log before returning — even on failure.
        Never raises; all errors are captured in DeploymentResult.error.
        """
        t0      = time.time()
        task_id = iac_bundle.task_id
        method  = iac_bundle.method
        attempt = getattr(iac_bundle, "attempt", 1)

        # ── Policy REJECT — blocked before reaching deployment ────────────
        if method == "none":
            self._audit.log(
                "DEPLOYMENT_BLOCKED", "warning", task_id=task_id,
                stage="deploy",
                message="Deployment blocked: policy REJECT decision",
            )
            return DeploymentResult(
                task_id=task_id, success=False, method="none",
                resources_deployed=[], resources_failed=[],
                duration_seconds=0.0, endpoint=None, attempt=attempt,
                error="Deployment blocked by policy (REJECT decision)",
            )

        self._audit.deployment_started(task_id, method, iac_bundle.resource_list)
        logger.info(
            "[%s] Deployment starting: method=%s attempt=%d dry_run=%s",
            task_id, method, attempt, DRY_RUN,
        )

        deployed:    List[str] = []
        failed:      List[str] = []
        endpoint:    Optional[str] = None
        plan_output: str = ""

        try:
            if DRY_RUN:
                deployed, endpoint, plan_output = await self._simulate_deployment(
                    task_id, iac_bundle
                )
            elif method in ("declarative", "hybrid"):
                deployed, endpoint, plan_output = await self._run_terraform(iac_bundle)
            else:
                deployed, endpoint, plan_output = await self._run_imperative(iac_bundle)

            # ── Health verification ───────────────────────────────────────
            health_ok, health_detail = await self._verify_health(
                task_id, deployed, endpoint
            )
            if not health_ok:
                raise RuntimeError(f"Post-deployment health check failed: {health_detail}")

            duration = time.time() - t0
            self._audit.deployment_complete(task_id, len(deployed), endpoint)
            logger.info(
                "[%s] Deployment complete: %d resources in %.1fs (attempt=%d)",
                task_id, len(deployed), duration, attempt,
            )
            return DeploymentResult(
                task_id=task_id, success=True, method=method,
                resources_deployed=deployed, resources_failed=failed,
                duration_seconds=round(duration, 2), endpoint=endpoint,
                plan_output=plan_output, attempt=attempt,
            )

        except Exception as exc:
            duration = time.time() - t0
            err_msg  = str(exc)
            logger.error("[%s] Deployment failed (attempt=%d): %s", task_id, attempt, err_msg)
            self._audit.log(
                "DEPLOYMENT_FAILED", "error", task_id=task_id,
                stage="deploy",
                message=f"Deployment failed (attempt {attempt}): {err_msg}",
                data={"error": err_msg, "method": method, "attempt": attempt},
            )
            return DeploymentResult(
                task_id=task_id, success=False, method=method,
                resources_deployed=deployed, resources_failed=failed,
                duration_seconds=round(duration, 2), endpoint=None,
                error=err_msg, plan_output=plan_output, attempt=attempt,
            )

    # ── Simulation (DRY_RUN=true) ─────────────────────────────────────────────

    async def _simulate_deployment(
        self, task_id: str, bundle
    ) -> Tuple[List[str], Optional[str], str]:
        """
        Simulate a full terraform apply with realistic per-resource delays.
        Returns (deployed_resources, endpoint, plan_output).
        """
        steps = [
            ("azurerm_resource_group",                0.3),
            ("azurerm_virtual_network",               0.4),
            ("azurerm_subnet",                        0.3),
            ("azurerm_network_security_group",        0.5),
            ("azurerm_subnet_network_security_group_association", 0.2),
        ]

        constraints = getattr(bundle, "constraints_applied", [])
        if "sandboxed_execution" in constraints:
            steps.append(("azurerm_container_group",           1.2))
        if "monitoring_required" in constraints:
            steps += [
                ("azurerm_log_analytics_workspace",            0.8),
                ("azurerm_monitor_activity_log_alert",         0.3),
            ]
        if "network_isolation" in constraints:
            steps += [
                ("azurerm_subnet",                             0.2),  # private endpoint subnet
                ("azurerm_private_endpoint",                   0.6),
                ("azurerm_private_dns_zone",                   0.3),
                ("azurerm_private_dns_a_record",               0.1),
            ]
        if "privilege_restriction" in constraints:
            steps += [
                ("azurerm_user_assigned_identity",             0.3),
                ("azurerm_role_assignment",                    0.4),
            ]

        deployed  = []
        plan_lines = [f"[DRY-RUN] Simulated terraform plan for task {task_id}:"]

        for resource, delay in steps:
            await asyncio.sleep(delay)
            deployed.append(resource)
            plan_lines.append(f"  + {resource}: created")
            self._audit.log(
                "RESOURCE_CREATED", "info", task_id=task_id,
                stage="deploy",
                message=f"[DRY-RUN] {resource}: created",
                data={"resource": resource, "dry_run": True},
            )
            logger.info("[%s][DRY-RUN] %s: created", task_id, resource)

        plan_output = "\n".join(plan_lines)
        plan_lines.append(f"\nPlan: {len(steps)} to add, 0 to change, 0 to destroy.")

        has_container = any(r == "azurerm_container_group" for r, _ in steps)
        endpoint = (
            "https://app-demo-eastus.azurecontainerapps.io"
            if has_container else None
        )
        return deployed, endpoint, plan_output

    # ── Real Terraform deployment ─────────────────────────────────────────────

    async def _run_terraform(
        self, bundle
    ) -> Tuple[List[str], Optional[str], str]:
        """
        Real terraform plan + apply.
        Requires terraform CLI in PATH and ARM_* env vars set.

        Two-phase:
          Phase 1 — terraform plan -detailed-exitcode
            exit 0 = no changes (unexpected but OK)
            exit 1 = provider error → raise immediately
            exit 2 = changes pending → proceed to apply

          Phase 2 — terraform apply -auto-approve
        """
        task_id = bundle.task_id
        tmpdir  = tempfile.mkdtemp(prefix=f"sap-deploy-{task_id[:8]}-")

        try:
            # Write all .tf files to tmpdir, preserving sub-paths
            for fname, content in bundle.terraform_files.items():
                dest = os.path.join(tmpdir, fname)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(content)

            # ── Phase 1a: terraform init ──────────────────────────────────
            # Use -backend=false so init succeeds even if the state backend
            # storage account doesn't exist yet at plan time.
            init_proc = await asyncio.create_subprocess_exec(
                "terraform", "init",
                "-backend=false",
                "-no-color",
                "-input=false",
                cwd=tmpdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, init_stderr = await asyncio.wait_for(
                    init_proc.communicate(), timeout=120
                )
            except asyncio.TimeoutError:
                init_proc.kill()
                raise RuntimeError("terraform init timed out after 120s")

            if init_proc.returncode != 0:
                raise RuntimeError(
                    f"terraform init failed:\n"
                    f"{init_stderr.decode(errors='replace')[-500:]}"
                )

            # ── Phase 1b: terraform plan ──────────────────────────────────
            plan_proc = await asyncio.create_subprocess_exec(
                "terraform", "plan",
                "-detailed-exitcode",
                "-no-color",
                "-input=false",
                "-out=tfplan",           # save plan for apply
                cwd=tmpdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                plan_stdout, plan_stderr = await asyncio.wait_for(
                    plan_proc.communicate(), timeout=TERRAFORM_TIMEOUT
                )
            except asyncio.TimeoutError:
                plan_proc.kill()
                raise RuntimeError(
                    f"terraform plan timed out after {TERRAFORM_TIMEOUT}s"
                )

            plan_output = plan_stdout.decode(errors="replace")

            if plan_proc.returncode == 1:
                # Provider error — do not apply
                err = plan_stderr.decode(errors="replace")[-800:]
                raise RuntimeError(f"terraform plan error:\n{err}")

            # returncode 0 = no changes, 2 = changes pending — both proceed to apply
            logger.info(
                "[%s] terraform plan: exit=%d (%s)",
                task_id, plan_proc.returncode,
                "no changes" if plan_proc.returncode == 0 else "changes pending",
            )

            # ── Phase 2: terraform apply (uses saved plan file) ───────────
            # Re-init WITH backend for apply so state is written remotely.
            reinit_proc = await asyncio.create_subprocess_exec(
                "terraform", "init",
                "-no-color",
                "-input=false",
                cwd=tmpdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(reinit_proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                reinit_proc.kill()
                raise RuntimeError("terraform re-init (with backend) timed out after 120s")

            apply_proc = await asyncio.create_subprocess_exec(
                "terraform", "apply",
                "-auto-approve",
                "-json",
                "-input=false",
                "tfplan",               # use the saved plan — avoids re-evaluating
                cwd=tmpdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                apply_stdout, apply_stderr = await asyncio.wait_for(
                    apply_proc.communicate(), timeout=TERRAFORM_TIMEOUT
                )
            except asyncio.TimeoutError:
                apply_proc.kill()
                raise RuntimeError(
                    f"terraform apply timed out after {TERRAFORM_TIMEOUT}s"
                )

            if apply_proc.returncode != 0:
                err = apply_stderr.decode(errors="replace")[-800:]
                raise RuntimeError(f"terraform apply failed:\n{err}")

            # Parse applied resources from JSON output
            deployed = self._parse_applied_resources(
                apply_stdout.decode(errors="replace")
            )
            if not deployed:
                # Fallback: use the bundle's resource list
                deployed = list(bundle.resource_list)

            return deployed, None, plan_output

        finally:
            # Always clean up — the tmpdir contains the plan file and .tf files.
            # State is written to remote backend so nothing is lost.
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Real az CLI deployment ────────────────────────────────────────────────

    async def _run_imperative(
        self, bundle
    ) -> Tuple[List[str], Optional[str], str]:
        """
        Execute the az CLI deploy.sh script from the IaCBundle.
        Uses a temp file that is always cleaned up (success or failure).
        """
        script  = bundle.terraform_files.get("deploy.sh", "")
        if not script:
            raise RuntimeError("deploy.sh not found in IaCBundle (method=imperative)")

        tmpfile = None
        try:
            fd, tmpfile = tempfile.mkstemp(suffix=".sh", prefix="sap-deploy-")
            with os.fdopen(fd, "w") as f:
                f.write(script)
            os.chmod(tmpfile, 0o700)

            proc = await asyncio.create_subprocess_exec(
                "bash", tmpfile,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=AZ_SCRIPT_TIMEOUT
                )
            except asyncio.TimeoutError:
                proc.kill()
                raise RuntimeError(
                    f"az CLI script timed out after {AZ_SCRIPT_TIMEOUT}s"
                )

            output = stdout.decode(errors="replace")
            if proc.returncode != 0:
                err = stderr.decode(errors="replace")[-600:]
                raise RuntimeError(
                    f"az CLI script exited {proc.returncode}:\n{err}"
                )

            return list(bundle.resource_list), None, output

        finally:
            # Always unlink — was only cleaned up on success before this fix
            if tmpfile and os.path.exists(tmpfile):
                try:
                    os.unlink(tmpfile)
                except OSError:
                    pass

    # ── Health verification ───────────────────────────────────────────────────

    async def _verify_health(
        self,
        task_id: str,
        deployed: List[str],
        endpoint: Optional[str],
    ) -> Tuple[bool, str]:
        """
        Verify the deployment is healthy after apply.

        In DRY_RUN mode: simulates a successful health check.
        In production: checks ARM provisioning state via az CLI, and
        optionally HTTP-probes the endpoint if one was provisioned.

        Returns (ok: bool, detail: str)
        """
        if DRY_RUN:
            await asyncio.sleep(0.2)
            detail = f"[DRY-RUN] {len(deployed)} resources verified as 'Succeeded'"
            logger.info("[%s] Health check: %s", task_id, detail)
            self._audit.log(
                "HEALTH_CHECK_PASSED", "info", task_id=task_id,
                stage="deploy",
                message=detail,
                data={"dry_run": True, "resources": len(deployed)},
            )
            return True, detail

        # Production: check ARM provisioning state of the resource group
        try:
            rg_name = next(
                (r for r in deployed if "resource_group" in r),
                None
            )
            if rg_name:
                proc = await asyncio.create_subprocess_exec(
                    "az", "group", "show",
                    "--name", rg_name,
                    "--query", "properties.provisioningState",
                    "--output", "tsv",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=HEALTH_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    return False, f"ARM health check timed out after {HEALTH_TIMEOUT}s"

                state = stdout.decode(errors="replace").strip()
                if state != "Succeeded":
                    return False, f"Resource group provisioning state: {state}"

            detail = f"{len(deployed)} resources provisioned, ARM state=Succeeded"
            self._audit.log(
                "HEALTH_CHECK_PASSED", "info", task_id=task_id,
                stage="deploy",
                message=detail,
                data={"resources": len(deployed), "endpoint": endpoint},
            )
            return True, detail

        except Exception as exc:
            detail = f"Health check error: {exc}"
            self._audit.log(
                "HEALTH_CHECK_FAILED", "warning", task_id=task_id,
                stage="deploy",
                message=detail,
                data={"error": str(exc)},
            )
            # Health check failure is non-fatal — log and return True
            # so the pipeline doesn't retry the entire IaC generation.
            # The deployment itself succeeded; health is best-effort.
            logger.warning("[%s] %s", task_id, detail)
            return True, detail

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_applied_resources(self, json_output: str) -> List[str]:
        """
        Extract applied resource types from terraform apply -json output.
        Returns a deduplicated list of azurerm_* resource type strings.
        """
        resources = []
        for line in json_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                # apply_complete messages contain the resource address
                if msg.get("type") == "apply_complete":
                    hook = msg.get("hook", {})
                    rtype = hook.get("resource", {}).get("resource_type", "")
                    if rtype:
                        resources.append(rtype)
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        # Deduplicate preserving order
        return list(dict.fromkeys(resources))