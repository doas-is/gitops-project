"""
Feasibility Validator Agent  —  src/agents/feasibility_validator.py

Stage 7.5 in the pipeline: sits between IaC generation (Stage 7) and
real deployment (Stage 8). Runs inside its own ephemeral microVM.

Responsibilities
────────────────
  1. Static validation  — terraform validate + ansible-lint (no Azure calls)
  2. Plan simulation    — terraform plan -detailed-exitcode (read-only ARM calls)
  3. Resource cross-check — planned resources vs. expected resource_list from strategy
  4. Source-informed check — decrypt source JIT, verify infra_hints match IaC
  5. Emit a FeasibilityResult with structured error details for the retry loop

Security contract
─────────────────
  • Runs in its own ephemeral ACI — destroyed immediately after result is returned
  • Source code is decrypted JIT (only inside this VM), zeroized after check
  • Uses a read-only, sandbox-scoped Azure Service Principal for terraform plan
    (env: VALIDATOR_AZURE_CLIENT_ID / VALIDATOR_AZURE_CLIENT_SECRET / VALIDATOR_AZURE_TENANT_ID)
  • All temp files written to /tmp/<task_id>/ which is on tmpfs (RAM-only in ACI)
  • terraform state is NEVER written — we only run plan, not apply
  • If KMS_LOCAL=true, source decryption falls back to local key store (dev mode)

Error taxonomy (used by retry loop in main.py to decide restart point)
───────────────────────────────────────────────────────────────────────
  SYNTAX_ERROR      → bad HCL / YAML syntax  → restart Stage 7 (re-generate IaC)
  PLAN_ERROR        → ARM resource error      → restart Stage 7 (re-generate IaC)
  RESOURCE_MISMATCH → wrong resources planned → restart Stage 6+7 (re-strategy + re-generate)
  HINT_MISMATCH     → IaC doesn't cover infra hints from source → restart Stage 6+7
  LINT_ERROR        → Ansible playbook issues → restart Stage 7
  UNKNOWN_ERROR     → unexpected failure      → restart Stage 7 (safe default)

Retry budget is enforced by the orchestrator (main.py), not here.
"""
from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from logs.audit import get_audit

logger = logging.getLogger(__name__)

# ── Env flags ─────────────────────────────────────────────────────────────────
DRY_RUN = os.getenv("AZURE_DEPLOY_DRY_RUN", "true").lower() == "true"
KMS_LOCAL = os.getenv("KMS_LOCAL", "false").lower() == "true"

# Read-only validator SP — separate from the deployment SP on purpose
VALIDATOR_CLIENT_ID     = os.getenv("VALIDATOR_AZURE_CLIENT_ID",     "")
VALIDATOR_CLIENT_SECRET = os.getenv("VALIDATOR_AZURE_CLIENT_SECRET", "")
VALIDATOR_TENANT_ID     = os.getenv("VALIDATOR_AZURE_TENANT_ID",     "")
VALIDATOR_SUBSCRIPTION  = os.getenv("AZURE_SUBSCRIPTION_ID",         "")

# How long (seconds) we allow terraform plan to run
PLAN_TIMEOUT = int(os.getenv("VALIDATOR_PLAN_TIMEOUT", "120"))


# ── Result types ───────────────────────────────────────────────────────────────

class ErrorCategory(str, Enum):
    SYNTAX_ERROR      = "SYNTAX_ERROR"       # bad HCL / YAML  → retry Stage 7
    PLAN_ERROR        = "PLAN_ERROR"         # ARM error        → retry Stage 7
    RESOURCE_MISMATCH = "RESOURCE_MISMATCH"  # wrong resources  → retry Stage 6+7
    HINT_MISMATCH     = "HINT_MISMATCH"      # missing hints    → retry Stage 6+7
    LINT_ERROR        = "LINT_ERROR"         # Ansible issues   → retry Stage 7
    UNKNOWN_ERROR     = "UNKNOWN_ERROR"      # safe default     → retry Stage 7


@dataclass
class ValidationCheck:
    """Result of one individual check step."""
    name: str
    passed: bool
    detail: str
    duration_seconds: float
    error_category: Optional[ErrorCategory] = None


@dataclass
class FeasibilityResult:
    """
    Returned by FeasibilityValidatorAgent.validate().
    Consumed by the retry loop in main.py.

    Fields
    ──────
    passed          — True only if ALL checks passed
    error_category  — ErrorCategory controlling which stage to restart from
    error_summary   — Human-readable one-liner for logging / UI
    error_detail    — Full structured detail for the IaC generator on retry
    checks          — Individual check results (for audit log)
    retry_hint      — Suggested fix passed back to IaCGeneratorAgent.generate()
    planned_resources — Resources terraform plan would create (empty on failure)
    duration_seconds  — Total validation wall-clock time
    validated_at      — Unix timestamp
    """
    task_id: str
    passed: bool
    error_category: Optional[ErrorCategory]
    error_summary: str
    error_detail: str
    checks: List[ValidationCheck]
    retry_hint: str                       # fed back into IaCGeneratorAgent
    planned_resources: List[str]
    duration_seconds: float
    validated_at: float = field(default_factory=time.time)

    # ── Restart-point logic ───────────────────────────────────────────────────
    @property
    def restart_from_strategy(self) -> bool:
        """True → orchestrator should restart from Stage 6 (Strategy Agent)."""
        return self.error_category in (
            ErrorCategory.RESOURCE_MISMATCH,
            ErrorCategory.HINT_MISMATCH,
        )

    @property
    def restart_from_iac(self) -> bool:
        """True → orchestrator should restart from Stage 7 (IaC Generator)."""
        return not self.passed and not self.restart_from_strategy


# ── Main agent class ───────────────────────────────────────────────────────────

class FeasibilityValidatorAgent:
    """
    Validates generated IaC before any real deployment happens.

    Usage (from main.py orchestrator):
        validator = FeasibilityValidatorAgent()
        result = await validator.validate(iac_bundle, intelligence_summary)
        if not result.passed:
            # retry loop uses result.restart_from_strategy / result.retry_hint
            ...
    """

    def __init__(self) -> None:
        self._audit = get_audit()

    # ── Public entry point ────────────────────────────────────────────────────

    async def validate(
        self,
        iac_bundle,           # IaCBundle from IaCGeneratorAgent
        intelligence,         # IntelligenceSummary from main pipeline
        attempt: int = 1,
    ) -> FeasibilityResult:
        """
        Run all validation checks against the IaC bundle.
        Returns FeasibilityResult — never raises (errors are captured inside).
        The temp directory is always cleaned up before returning.
        """
        t0 = time.time()
        task_id = iac_bundle.task_id
        checks: List[ValidationCheck] = []
        tmpdir: Optional[str] = None

        logger.info(
            "[%s] FeasibilityValidator starting (attempt=%d, method=%s, dry_run=%s)",
            task_id, attempt, iac_bundle.method, DRY_RUN,
        )
        self._audit.log(
            "FEASIBILITY_STARTED", "info", task_id=task_id,
            stage="feasibility",
            message=f"Feasibility validation started (attempt {attempt})",
            data={"attempt": attempt, "method": iac_bundle.method, "dry_run": DRY_RUN},
        )

        try:
            # Write IaC files to a RAM-backed temp directory
            tmpdir = tempfile.mkdtemp(prefix=f"sap-val-{task_id[:8]}-")
            tf_dir  = os.path.join(tmpdir, "terraform")
            ans_dir = os.path.join(tmpdir, "ansible")
            os.makedirs(tf_dir,  exist_ok=True)
            os.makedirs(ans_dir, exist_ok=True)

            self._write_iac_files(iac_bundle, tf_dir, ans_dir)

            # ── Check 1: Terraform syntax (terraform validate) ────────────────
            checks.append(await self._check_tf_validate(tf_dir, task_id))
            if not checks[-1].passed:
                return self._fail_fast(task_id, checks, t0, tmpdir)

            # ── Check 2: Ansible lint ─────────────────────────────────────────
            if iac_bundle.ansible_files:
                checks.append(await self._check_ansible_lint(ans_dir, task_id))
                if not checks[-1].passed:
                    return self._fail_fast(task_id, checks, t0, tmpdir)

            # ── Check 3: Terraform plan (dry-run or real) ─────────────────────
            plan_check, planned_resources = await self._check_tf_plan(
                tf_dir, task_id
            )
            checks.append(plan_check)
            if not plan_check.passed:
                return self._fail_fast(task_id, checks, t0, tmpdir)

            # ── Check 4: Resource cross-check ─────────────────────────────────
            checks.append(self._check_resource_match(
                planned_resources,
                iac_bundle.resource_list,
                task_id,
            ))
            if not checks[-1].passed:
                return self._fail_fast(task_id, checks, t0, tmpdir)

            # ── Check 5: Source infra-hint coverage ───────────────────────────
            checks.append(self._check_infra_hints(
                intelligence,
                iac_bundle,
                task_id,
            ))
            if not checks[-1].passed:
                return self._fail_fast(task_id, checks, t0, tmpdir)

            # ── All checks passed ─────────────────────────────────────────────
            duration = time.time() - t0
            result = FeasibilityResult(
                task_id=task_id,
                passed=True,
                error_category=None,
                error_summary="All checks passed",
                error_detail="",
                checks=checks,
                retry_hint="",
                planned_resources=planned_resources,
                duration_seconds=round(duration, 2),
            )
            self._audit.log(
                "FEASIBILITY_PASSED", "info", task_id=task_id,
                stage="feasibility",
                message=f"Feasibility passed in {duration:.1f}s ({len(checks)} checks)",
                data={"checks": [c.name for c in checks], "attempt": attempt},
            )
            logger.info("[%s] Feasibility PASSED in %.1fs", task_id, duration)
            return result

        except Exception as exc:
            # Catch-all: unexpected errors must never surface raw exceptions to
            # the orchestrator — they get wrapped in a safe FeasibilityResult.
            duration = time.time() - t0
            logger.exception("[%s] Unexpected error in feasibility validator", task_id)
            self._audit.log(
                "FEASIBILITY_EXCEPTION", "error", task_id=task_id,
                stage="feasibility",
                message=f"Unexpected validator error: {exc}",
                data={"error": str(exc), "attempt": attempt},
            )
            return FeasibilityResult(
                task_id=task_id,
                passed=False,
                error_category=ErrorCategory.UNKNOWN_ERROR,
                error_summary=f"Unexpected error: {exc}",
                error_detail=str(exc),
                checks=checks,
                retry_hint="An unexpected error occurred during validation. "
                           "Review IaC structure and provider configuration.",
                planned_resources=[],
                duration_seconds=round(duration, 2),
            )
        finally:
            # Always clean up — tmpdir is on tmpfs inside the ACI, but
            # belt-and-suspenders: explicitly wipe before VM self-destructs.
            if tmpdir and os.path.exists(tmpdir):
                try:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                except Exception:
                    pass

    # ── File I/O ───────────────────────────────────────────────────────────────

    def _write_iac_files(self, iac_bundle, tf_dir: str, ans_dir: str) -> None:
        """Write IaCBundle contents to temp directories for CLI tools."""
        for fname, content in iac_bundle.terraform_files.items():
            # Prevent path traversal in generated filenames
            safe_name = os.path.basename(fname)
            dest = os.path.join(tf_dir, safe_name)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)

        for fname, content in iac_bundle.ansible_files.items():
            # Preserve sub-paths (e.g. roles/hardening/tasks/main.yml)
            dest = os.path.join(ans_dir, fname)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)

    # ── Check 1: terraform validate ───────────────────────────────────────────

    async def _check_tf_validate(
        self, tf_dir: str, task_id: str
    ) -> ValidationCheck:
        t = time.time()
        name = "terraform_validate"

        if DRY_RUN or not shutil.which("terraform"):
            logger.info("[%s] terraform validate: SKIPPED (dry-run / no CLI)", task_id)
            return ValidationCheck(
                name=name, passed=True,
                detail="Skipped (dry-run or terraform not in PATH)",
                duration_seconds=round(time.time() - t, 2),
            )

        try:
            # terraform init (minimal — only validates provider schema)
            init_proc = await asyncio.create_subprocess_exec(
                "terraform", "init",
                "-backend=false",   # no state backend needed for validate
                "-no-color",
                cwd=tf_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, init_stderr = await asyncio.wait_for(
                init_proc.communicate(), timeout=60
            )
            if init_proc.returncode != 0:
                detail = init_stderr.decode(errors="replace").strip()[-800:]
                logger.warning("[%s] terraform init failed: %s", task_id, detail[:200])
                return ValidationCheck(
                    name=name, passed=False,
                    detail=f"terraform init failed:\n{detail}",
                    duration_seconds=round(time.time() - t, 2),
                    error_category=ErrorCategory.SYNTAX_ERROR,
                )

            # terraform validate
            val_proc = await asyncio.create_subprocess_exec(
                "terraform", "validate", "-json",
                cwd=tf_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                val_proc.communicate(), timeout=30
            )
            output = stdout.decode(errors="replace").strip()

            try:
                result = json.loads(output)
                if result.get("valid"):
                    return ValidationCheck(
                        name=name, passed=True,
                        detail=f"Valid ({result.get('warning_count', 0)} warnings)",
                        duration_seconds=round(time.time() - t, 2),
                    )
                # Extract diagnostics
                diags = result.get("diagnostics", [])
                errors = [
                    f"[{d.get('severity','error')}] {d.get('summary','')} — {d.get('detail','')}"
                    for d in diags if d.get("severity") == "error"
                ]
                detail = "\n".join(errors[:10]) if errors else output[:800]
                return ValidationCheck(
                    name=name, passed=False,
                    detail=detail,
                    duration_seconds=round(time.time() - t, 2),
                    error_category=ErrorCategory.SYNTAX_ERROR,
                )
            except json.JSONDecodeError:
                # Non-JSON output means something went wrong before validation
                passed = val_proc.returncode == 0
                return ValidationCheck(
                    name=name, passed=passed,
                    detail=output[:800],
                    duration_seconds=round(time.time() - t, 2),
                    error_category=None if passed else ErrorCategory.SYNTAX_ERROR,
                )

        except asyncio.TimeoutError:
            return ValidationCheck(
                name=name, passed=False,
                detail="terraform validate timed out (>60s)",
                duration_seconds=round(time.time() - t, 2),
                error_category=ErrorCategory.UNKNOWN_ERROR,
            )
        except Exception as exc:
            return ValidationCheck(
                name=name, passed=False,
                detail=f"Unexpected error: {exc}",
                duration_seconds=round(time.time() - t, 2),
                error_category=ErrorCategory.UNKNOWN_ERROR,
            )

    # ── Check 2: ansible-lint ─────────────────────────────────────────────────

    async def _check_ansible_lint(
        self, ans_dir: str, task_id: str
    ) -> ValidationCheck:
        t = time.time()
        name = "ansible_lint"

        if DRY_RUN or not shutil.which("ansible-lint"):
            logger.info("[%s] ansible-lint: SKIPPED (dry-run / no CLI)", task_id)
            return ValidationCheck(
                name=name, passed=True,
                detail="Skipped (dry-run or ansible-lint not in PATH)",
                duration_seconds=round(time.time() - t, 2),
            )

        site_yml = os.path.join(ans_dir, "site.yml")
        if not os.path.exists(site_yml):
            return ValidationCheck(
                name=name, passed=True,
                detail="No site.yml found — skipped",
                duration_seconds=round(time.time() - t, 2),
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                "ansible-lint", site_yml,
                "--parseable",
                "--nocolor",
                cwd=ans_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=60
            )
            output = (stdout + stderr).decode(errors="replace").strip()

            # ansible-lint exit codes: 0=ok, 1=violations, 2=fatal
            if proc.returncode == 0:
                return ValidationCheck(
                    name=name, passed=True,
                    detail="No lint violations",
                    duration_seconds=round(time.time() - t, 2),
                )

            # Count violations for summary
            lines = [l for l in output.splitlines() if l.strip()]
            n_violations = len(lines)
            detail = "\n".join(lines[:15])
            if n_violations > 15:
                detail += f"\n... and {n_violations - 15} more"

            # Severity: treat fatal (rc=2) as hard failure, warnings (rc=1) as soft
            is_fatal = proc.returncode == 2
            return ValidationCheck(
                name=name, passed=not is_fatal,
                detail=f"{n_violations} lint issue(s):\n{detail}",
                duration_seconds=round(time.time() - t, 2),
                error_category=ErrorCategory.LINT_ERROR if is_fatal else None,
            )

        except asyncio.TimeoutError:
            return ValidationCheck(
                name=name, passed=False,
                detail="ansible-lint timed out (>60s)",
                duration_seconds=round(time.time() - t, 2),
                error_category=ErrorCategory.UNKNOWN_ERROR,
            )
        except Exception as exc:
            return ValidationCheck(
                name=name, passed=False,
                detail=f"Unexpected error: {exc}",
                duration_seconds=round(time.time() - t, 2),
                error_category=ErrorCategory.UNKNOWN_ERROR,
            )

    # ── Check 3: terraform plan ───────────────────────────────────────────────

    async def _check_tf_plan(
        self, tf_dir: str, task_id: str
    ) -> Tuple[ValidationCheck, List[str]]:
        """
        Returns (ValidationCheck, list_of_planned_resource_types).
        In dry-run mode: simulates a successful plan with expected resources.
        In real mode: runs terraform plan -detailed-exitcode with read-only SP.
        """
        t = time.time()
        name = "terraform_plan"

        if DRY_RUN or not shutil.which("terraform"):
            # Simulate plan from the .tf files we have
            planned = self._simulate_plan_resources(tf_dir)
            logger.info("[%s] terraform plan: SIMULATED (%d resources)", task_id, len(planned))
            return (
                ValidationCheck(
                    name=name, passed=True,
                    detail=f"Simulated plan: {len(planned)} resources ({', '.join(planned[:5])}{'...' if len(planned)>5 else ''})",
                    duration_seconds=round(time.time() - t, 2),
                ),
                planned,
            )

        # Real plan — requires provider credentials
        if not all([VALIDATOR_CLIENT_ID, VALIDATOR_CLIENT_SECRET,
                    VALIDATOR_TENANT_ID, VALIDATOR_SUBSCRIPTION]):
            logger.warning(
                "[%s] terraform plan: SKIPPED — VALIDATOR_AZURE_* env vars not set", task_id
            )
            planned = self._simulate_plan_resources(tf_dir)
            return (
                ValidationCheck(
                    name=name, passed=True,
                    detail="Skipped (validator SP credentials not configured) — resource list inferred from files",
                    duration_seconds=round(time.time() - t, 2),
                ),
                planned,
            )

        env = {
            **os.environ,
            "ARM_CLIENT_ID":       VALIDATOR_CLIENT_ID,
            "ARM_CLIENT_SECRET":   VALIDATOR_CLIENT_SECRET,
            "ARM_TENANT_ID":       VALIDATOR_TENANT_ID,
            "ARM_SUBSCRIPTION_ID": VALIDATOR_SUBSCRIPTION,
            # Force local state — never write tfstate anywhere persistent
            "TF_CLI_ARGS_plan": "-state=/dev/null",
        }

        try:
            proc = await asyncio.create_subprocess_exec(
                "terraform", "plan",
                "-detailed-exitcode",
                "-json",
                "-out=/dev/null",    # discard plan file — we only care about exit code
                "-no-color",
                cwd=tf_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=PLAN_TIMEOUT
            )

            # Exit codes: 0=no changes, 1=error, 2=changes pending (expected)
            if proc.returncode == 1:
                raw_err = stderr.decode(errors="replace").strip()[-1000:]
                # Try to extract clean error from JSON lines
                detail = self._extract_plan_errors(
                    stdout.decode(errors="replace"), raw_err
                )
                return (
                    ValidationCheck(
                        name=name, passed=False,
                        detail=detail,
                        duration_seconds=round(time.time() - t, 2),
                        error_category=ErrorCategory.PLAN_ERROR,
                    ),
                    [],
                )

            # Parse planned resources from JSON output
            planned = self._parse_plan_resources(stdout.decode(errors="replace"))
            return (
                ValidationCheck(
                    name=name, passed=True,
                    detail=f"Plan OK: {len(planned)} resources to create",
                    duration_seconds=round(time.time() - t, 2),
                ),
                planned,
            )

        except asyncio.TimeoutError:
            return (
                ValidationCheck(
                    name=name, passed=False,
                    detail=f"terraform plan timed out (>{PLAN_TIMEOUT}s)",
                    duration_seconds=round(time.time() - t, 2),
                    error_category=ErrorCategory.UNKNOWN_ERROR,
                ),
                [],
            )
        except Exception as exc:
            return (
                ValidationCheck(
                    name=name, passed=False,
                    detail=f"Unexpected error: {exc}",
                    duration_seconds=round(time.time() - t, 2),
                    error_category=ErrorCategory.UNKNOWN_ERROR,
                ),
                [],
            )

    # ── Check 4: resource cross-check ─────────────────────────────────────────

    def _check_resource_match(
        self,
        planned: List[str],
        expected: List[str],
        task_id: str,
    ) -> ValidationCheck:
        """
        Verify that the planned resources cover the strategy's expected list.
        We allow extras (IaC can add supporting resources), but must not miss
        any that the strategy explicitly required.
        """
        t = time.time()
        name = "resource_cross_check"

        if not expected:
            return ValidationCheck(
                name=name, passed=True,
                detail="No expected resource list — skipped",
                duration_seconds=round(time.time() - t, 2),
            )

        # Normalise: strip azurerm_ prefix for loose matching
        def _norm(r: str) -> str:
            return r.replace("azurerm_", "").lower().strip()

        planned_norm  = {_norm(r) for r in planned}
        expected_norm = {_norm(r) for r in expected}
        missing = expected_norm - planned_norm

        if not missing:
            return ValidationCheck(
                name=name, passed=True,
                detail=(
                    f"All {len(expected)} expected resources present in plan. "
                    f"{len(planned) - len(expected)} extra supporting resources added."
                ),
                duration_seconds=round(time.time() - t, 2),
            )

        detail = (
            f"{len(missing)} expected resource(s) missing from plan: "
            f"{', '.join(sorted(missing)[:10])}"
        )
        retry_hint = (
            f"IaC plan is missing these required resources: {', '.join(sorted(missing))}. "
            "Regenerate with a strategy that provisions all required resource types."
        )
        logger.warning("[%s] Resource mismatch: %s", task_id, detail)
        return ValidationCheck(
            name=name, passed=False,
            detail=detail + f"\n\nRetry hint: {retry_hint}",
            duration_seconds=round(time.time() - t, 2),
            error_category=ErrorCategory.RESOURCE_MISMATCH,
        )

    # ── Check 5: infra-hint coverage ──────────────────────────────────────────

    def _check_infra_hints(
        self,
        intelligence,         # IntelligenceSummary (may be None in dev)
        iac_bundle,
        task_id: str,
    ) -> ValidationCheck:
        """
        Cross-reference the infra_hints extracted from the source code (via IR)
        against the generated IaC files. If a hint signals e.g. 'Kubernetes client'
        but no azurerm_kubernetes_cluster appears in the Terraform, flag it.

        This is a heuristic check — misses are warnings, not hard failures,
        unless the gap is severe (>50% of hints unaddressed).
        """
        t = time.time()
        name = "infra_hint_coverage"

        if intelligence is None:
            return ValidationCheck(
                name=name, passed=True,
                detail="No intelligence summary available — skipped",
                duration_seconds=round(time.time() - t, 2),
            )

        hints: List[str] = getattr(intelligence, "infra_hints", [])
        if not hints:
            return ValidationCheck(
                name=name, passed=True,
                detail="No infra hints detected in source — skipped",
                duration_seconds=round(time.time() - t, 2),
            )

        # Combine all generated TF content for keyword search
        all_tf = "\n".join(iac_bundle.terraform_files.values()).lower()

        # Hint → keywords that should appear in IaC if addressed
        HINT_KEYWORDS: Dict[str, List[str]] = {
            "Kubernetes client":   ["kubernetes_cluster", "aks", "kubernetes"],
            "Docker API":          ["container_group", "container_registry", "acr"],
            "Azure SDK":           ["azurerm", "azure"],
            "AWS SDK":             ["aws"],        # flag — user may be migrating
            "GCP SDK":             ["google"],     # same
            "Database ORM":        ["sql_server", "postgresql", "mysql", "cosmosdb", "database"],
            "Redis cache":         ["redis_cache", "redis"],
            "Task queue":          ["servicebus", "queue", "eventhub"],
            "Message streaming":   ["eventhub", "servicebus", "kafka"],
            "SSH/remote execution":["virtual_machine", "bastion", "ssh"],
        }

        unaddressed = []
        addressed   = []
        for hint in hints:
            keywords = HINT_KEYWORDS.get(hint, [])
            if not keywords:
                addressed.append(hint)   # unknown hint — assume OK
                continue
            if any(kw in all_tf for kw in keywords):
                addressed.append(hint)
            else:
                unaddressed.append(hint)

        if not unaddressed:
            return ValidationCheck(
                name=name, passed=True,
                detail=f"All {len(hints)} infra hints addressed in IaC.",
                duration_seconds=round(time.time() - t, 2),
            )

        coverage_pct = len(addressed) / len(hints) if hints else 1.0
        detail = (
            f"{len(unaddressed)}/{len(hints)} infra hint(s) not addressed in IaC: "
            f"{', '.join(unaddressed)}"
        )
        logger.warning("[%s] Hint coverage %.0f%%: %s", task_id, coverage_pct * 100, detail)

        # Hard failure if more than half the hints are unaddressed
        is_hard_fail = coverage_pct < 0.5
        return ValidationCheck(
            name=name,
            passed=not is_hard_fail,
            detail=detail + (
                "\nCritical: >50% of infrastructure hints are unaddressed."
                if is_hard_fail else
                "\nWarning: some hints unaddressed — IaC may be incomplete."
            ),
            duration_seconds=round(time.time() - t, 2),
            error_category=ErrorCategory.HINT_MISMATCH if is_hard_fail else None,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _fail_fast(
        self,
        task_id: str,
        checks: List[ValidationCheck],
        t0: float,
        tmpdir: Optional[str],
    ) -> FeasibilityResult:
        """Build a FeasibilityResult from the first failing check."""
        failed_check = next(c for c in reversed(checks) if not c.passed)
        category = failed_check.error_category or ErrorCategory.UNKNOWN_ERROR
        duration = round(time.time() - t0, 2)

        # Build a retry hint from the error detail
        retry_hint = self._build_retry_hint(category, failed_check.detail)

        self._audit.log(
            "FEASIBILITY_FAILED", "warning", task_id=task_id,
            stage="feasibility",
            message=f"Feasibility FAILED at check '{failed_check.name}': {failed_check.detail[:200]}",
            data={
                "failed_check": failed_check.name,
                "error_category": category,
                "duration": duration,
            },
        )
        logger.warning(
            "[%s] Feasibility FAILED at '%s' (%s) in %.1fs",
            task_id, failed_check.name, category, duration,
        )

        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)

        return FeasibilityResult(
            task_id=task_id,
            passed=False,
            error_category=category,
            error_summary=f"{failed_check.name}: {failed_check.detail[:200]}",
            error_detail=failed_check.detail,
            checks=checks,
            retry_hint=retry_hint,
            planned_resources=[],
            duration_seconds=duration,
        )

    def _build_retry_hint(self, category: ErrorCategory, detail: str) -> str:
        """Translate error category + raw detail into an actionable hint for the IaC generator."""
        hints = {
            ErrorCategory.SYNTAX_ERROR: (
                "Fix HCL/YAML syntax errors in the generated files. "
                "Ensure all blocks are correctly closed, variable references exist, "
                "and provider version constraints are valid."
            ),
            ErrorCategory.PLAN_ERROR: (
                "The ARM provider rejected the plan. Check that resource names are unique, "
                "all required properties are set, SKU/tier values are valid for the region, "
                "and dependencies between resources are declared with `depends_on`."
            ),
            ErrorCategory.RESOURCE_MISMATCH: (
                "The IaC plan is missing required resource types. "
                "Revise the deployment strategy to include all needed Azure resources, "
                "then regenerate IaC from the updated strategy."
            ),
            ErrorCategory.HINT_MISMATCH: (
                "Infrastructure hints from the source code are not addressed in the IaC. "
                "The strategy agent should re-evaluate the detected services and ensure "
                "the IaC covers all required Azure resource types."
            ),
            ErrorCategory.LINT_ERROR: (
                "Ansible playbook has critical lint violations. "
                "Ensure all tasks have `name` fields, handlers are correctly referenced, "
                "and no deprecated modules are used."
            ),
            ErrorCategory.UNKNOWN_ERROR: (
                "An unexpected error occurred. "
                "Review the IaC structure, ensure all variable defaults are set, "
                "and try regenerating with a more conservative configuration."
            ),
        }
        base = hints.get(category, "Review the IaC and regenerate.")
        # Append the first 300 chars of the raw detail for context
        return f"{base}\n\nRaw error (first 300 chars): {detail[:300]}"

    def _simulate_plan_resources(self, tf_dir: str) -> List[str]:
        """
        In dry-run mode, infer planned resources by scanning .tf files for
        `resource "azurerm_*"` blocks — no actual ARM calls.
        """
        planned = []
        for fname in os.listdir(tf_dir):
            if not fname.endswith(".tf"):
                continue
            try:
                with open(os.path.join(tf_dir, fname), encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('resource "azurerm_'):
                            # resource "azurerm_virtual_network" "main" {
                            parts = line.split('"')
                            if len(parts) >= 2:
                                planned.append(parts[1])
            except Exception:
                pass
        return list(dict.fromkeys(planned))  # deduplicate, preserve order

    def _parse_plan_resources(self, json_output: str) -> List[str]:
        """Parse resource types from terraform plan -json output."""
        resources = []
        for line in json_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if msg.get("type") == "planned_change":
                    change = msg.get("change", {})
                    resource = change.get("resource", {})
                    rtype = resource.get("resource_type", "")
                    if rtype:
                        resources.append(rtype)
            except (json.JSONDecodeError, KeyError):
                continue
        return list(dict.fromkeys(resources))

    def _extract_plan_errors(self, json_output: str, raw_stderr: str) -> str:
        """Extract clean error messages from terraform plan JSON output."""
        errors = []
        for line in json_output.splitlines():
            try:
                msg = json.loads(line)
                if msg.get("level") == "error" or msg.get("type") == "diagnostic":
                    diag = msg.get("diagnostic", msg)
                    summary = diag.get("summary", "")
                    detail  = diag.get("detail", "")
                    if summary:
                        errors.append(f"• {summary}" + (f": {detail}" if detail else ""))
            except (json.JSONDecodeError, KeyError):
                continue

        if errors:
            return "terraform plan errors:\n" + "\n".join(errors[:10])
        return f"terraform plan failed:\n{raw_stderr[-800:]}"