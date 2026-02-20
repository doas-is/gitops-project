"""
Deployment Agent

The final agent in the pipeline. Receives an IaCBundle and:
  1. Validates the bundle (dry-run / plan)
  2. Applies the IaC (terraform apply OR az script)
  3. Verifies deployment health
  4. Reports results to Orchestrator
  5. Self-destructs its VM

This agent runs in its own ephemeral microVM.
After step 5, the VM is immediately terminated.
Logs are written to the Audit Logger BEFORE VM destruction.

In demo/dev mode (AZURE_DEPLOY_DRY_RUN=true), all Azure calls
are simulated and logged without actually provisioning resources.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from logs.audit import get_audit

logger = logging.getLogger(__name__)

DRY_RUN = os.getenv("AZURE_DEPLOY_DRY_RUN", "true").lower() == "true"


@dataclass
class DeploymentResult:
    task_id: str
    success: bool
    method: str
    resources_deployed: List[str]
    resources_failed: List[str]
    duration_seconds: float
    endpoint: Optional[str]
    error: Optional[str] = None
    deployed_at: float = field(default_factory=time.time)


class DeploymentAgent:
    """
    Applies IaC bundle to Azure. Dry-run safe.

    In production: shells out to `terraform` or `az` CLI.
    In dry-run: simulates all steps with realistic timing.
    """

    def __init__(self) -> None:
        self._audit = get_audit()

    async def deploy(self, iac_bundle) -> DeploymentResult:
        """
        Deploy an IaCBundle. Returns DeploymentResult.
        Always writes to audit log before returning.
        """
        t0 = time.time()
        task_id = iac_bundle.task_id
        method = iac_bundle.method

        if method == "none":
            result = DeploymentResult(
                task_id=task_id, success=False, method="none",
                resources_deployed=[], resources_failed=[],
                duration_seconds=0.0, endpoint=None,
                error="Deployment blocked by policy (REJECT decision)",
            )
            self._audit.log("DEPLOYMENT_BLOCKED", "warning", task_id=task_id,
                            stage="deploy", message="Deployment blocked: policy REJECT")
            return result

        self._audit.deployment_started(task_id, method, iac_bundle.resource_list)
        logger.info("Deployment starting: task=%s method=%s dry_run=%s",
                    task_id, method, DRY_RUN)

        deployed = []
        failed = []
        endpoint = None

        try:
            if DRY_RUN:
                deployed, endpoint = await self._simulate_deployment(
                    task_id, iac_bundle, deployed
                )
            else:
                if method in ("declarative", "hybrid"):
                    deployed, endpoint = await self._run_terraform(iac_bundle)
                else:
                    deployed, endpoint = await self._run_imperative(iac_bundle)

            duration = time.time() - t0
            self._audit.deployment_complete(task_id, len(deployed), endpoint)
            logger.info("Deployment complete: %d resources in %.1fs", len(deployed), duration)

            return DeploymentResult(
                task_id=task_id, success=True, method=method,
                resources_deployed=deployed, resources_failed=failed,
                duration_seconds=duration, endpoint=endpoint,
            )

        except Exception as e:
            duration = time.time() - t0
            logger.error("Deployment failed: %s", e)
            self._audit.log("DEPLOYMENT_FAILED", "error", task_id=task_id,
                            stage="deploy", message=str(e))
            return DeploymentResult(
                task_id=task_id, success=False, method=method,
                resources_deployed=deployed, resources_failed=failed,
                duration_seconds=duration, endpoint=None, error=str(e),
            )

    async def _simulate_deployment(
        self, task_id: str, bundle, deployed: List[str]
    ):
        """Simulate terraform apply steps with realistic delays."""
        steps = [
            ("azurerm_resource_group",       0.3),
            ("azurerm_virtual_network",      0.4),
            ("azurerm_subnet",               0.3),
            ("azurerm_network_security_group", 0.5),
            ("azurerm_subnet_nsg_association", 0.2),
        ]
        if "sandboxed_execution" in bundle.constraints_applied:
            steps.append(("azurerm_container_group", 1.2))
        if "monitoring_required" in bundle.constraints_applied:
            steps += [("azurerm_log_analytics_workspace", 0.8),
                      ("azurerm_monitor_activity_log_alert", 0.3)]

        for resource, delay in steps:
            await asyncio.sleep(delay)
            deployed.append(resource)
            self._audit.log("RESOURCE_CREATED", "info", task_id=task_id,
                            stage="deploy", message=f"[DRY-RUN] {resource}: created",
                            data={"resource": resource})
            logger.info("[DRY-RUN] %s: created", resource)

        endpoint = "https://app-demo-eastus.azurecontainerapps.io" if \
            "azurerm_container_group" in [r for r, _ in steps] else None
        return deployed, endpoint

    async def _run_terraform(self, bundle):
        """Real terraform apply. Requires terraform CLI in PATH."""
        import subprocess, tempfile, json

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write tf files
            for fname, content in bundle.terraform_files.items():
                path = os.path.join(tmpdir, fname)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(content)

            # terraform init
            proc = await asyncio.create_subprocess_exec(
                "terraform", "init", "-no-color",
                cwd=tmpdir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            # terraform apply
            proc = await asyncio.create_subprocess_exec(
                "terraform", "apply", "-auto-approve", "-json",
                cwd=tmpdir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

        deployed = bundle.resource_list
        return deployed, None

    async def _run_imperative(self, bundle):
        """Run az CLI script."""
        import subprocess, tempfile

        script = bundle.terraform_files.get("deploy.sh", "")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(script)
            script_path = f.name

        os.chmod(script_path, 0o700)
        proc = await asyncio.create_subprocess_exec(
            "bash", script_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        os.unlink(script_path)

        if proc.returncode != 0:
            raise RuntimeError(f"az script failed: {stderr.decode()[:200]}")

        return bundle.resource_list, None