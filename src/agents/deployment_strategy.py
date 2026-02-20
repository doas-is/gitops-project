"""
Deployment Strategy Agent

Analyses the code structure (via PolicyDecision + IR metrics) and decides:
  - DECLARATIVE  → Terraform + Ansible (idempotent, state-managed)
  - IMPERATIVE   → Azure CLI / ARM scripts (procedural, step-by-step)
  - HYBRID       → Terraform for infra + imperative hooks for runtime config

Decision criteria:
  Declarative preferred when:
    - Codebase is stateless / microservice-oriented (high FUNC_DEF ratio, low GLOBAL)
    - Low cyclomatic complexity (straightforward service boundaries)
    - Policy approved with zero or few constraints
    - Import count suggests standard cloud-native libraries

  Imperative preferred when:
    - High stateful complexity (many CLASS_DEF + ASSIGN + LOOP)
    - Constraints require custom runtime hardening steps
    - Complex dependency graph needs ordered provisioning
    - HITL was required (extra control needed)

  Hybrid when:
    - Approved with constraints (Terraform infra + Ansible hardening)
    - Mixed stateless + stateful components detected

This agent sees ONLY PolicyDecision and aggregate IR metrics — no code.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class StrategyDecision:
    method: str                    # "declarative" | "imperative" | "hybrid"
    primary_tool: str              # "terraform" | "azure_cli" | "arm"
    secondary_tool: Optional[str]  # "ansible" | None
    reasoning: List[str]           # Why this was chosen
    confidence: float
    estimated_resources: List[str] # What Azure resources will be provisioned
    constraints_applied: List[str]
    task_id: str
    decided_at: float


class DeploymentStrategyAgent:
    """
    Decides deployment method from PolicyDecision + IR aggregate metrics.
    Never sees raw code — only structured metrics.
    """

    def decide(
        self,
        policy_decision,          # PolicyDecision schema object
        ir_metrics: Dict,         # Aggregate IR metrics from RiskAssessment
        task_id: str,
    ) -> StrategyDecision:
        """
        Analyse the policy decision and IR metrics to choose deployment strategy.
        """
        decision_str = policy_decision.decision
        constraints = [c.constraint_type for c in policy_decision.constraints]
        risk = getattr(policy_decision, 'risk_summary', '')
        hitl_required = getattr(policy_decision, 'hitl_required', False)
        confidence = policy_decision.confidence

        # IR structural signals
        total_nodes = ir_metrics.get("total_ir_nodes", 0)
        privilege_count = ir_metrics.get("privileged_api_count", 0)
        high_risk_files = ir_metrics.get("high_risk_file_count", 0)
        anomalous = ir_metrics.get("anomalous_pattern_count", 0)
        aggregate_risk = ir_metrics.get("aggregate_risk", 0.0)

        reasoning: List[str] = []
        method: str
        primary_tool: str
        secondary_tool: Optional[str]

        # ── Decision tree ────────────────────────────────────────

        if decision_str == "REJECT":
            # Rejected: no deployment, but record the strategy intent
            method = "none"
            primary_tool = "none"
            secondary_tool = None
            reasoning.append("Policy REJECTED deployment — no IaC will be generated")
            return StrategyDecision(
                method=method, primary_tool=primary_tool, secondary_tool=secondary_tool,
                reasoning=reasoning, confidence=confidence,
                estimated_resources=[], constraints_applied=constraints,
                task_id=task_id, decided_at=time.time(),
            )

        # Signals favouring IMPERATIVE
        imperative_signals = 0
        if hitl_required:
            imperative_signals += 2
            reasoning.append("HITL was required — extra procedural control preferred")
        if privilege_count > 5:
            imperative_signals += 1
            reasoning.append(f"High privilege API count ({privilege_count}) — ordered provisioning needed")
        if high_risk_files > 2:
            imperative_signals += 1
            reasoning.append(f"{high_risk_files} high-risk files — imperative hardening steps safer")
        if "network_isolation" in constraints:
            imperative_signals += 1
            reasoning.append("Network isolation constraint — NSG rules need ordered application")

        # Signals favouring DECLARATIVE
        declarative_signals = 0
        if aggregate_risk < 0.4:
            declarative_signals += 2
            reasoning.append(f"Low aggregate risk ({aggregate_risk:.2f}) — declarative IaC is safe")
        if total_nodes < 300 and privilege_count == 0:
            declarative_signals += 2
            reasoning.append("Small, low-privilege codebase — Terraform state management ideal")
        if decision_str == "APPROVE" and not hitl_required:
            declarative_signals += 2
            reasoning.append("Clean policy approval — Terraform + Ansible standard flow")

        # Signals favouring HYBRID
        has_constraints = len(constraints) > 0
        if has_constraints and decision_str == "APPROVE_WITH_CONSTRAINTS":
            reasoning.append(f"Constraints present ({', '.join(constraints)}) — Terraform infra + Ansible hardening")

        # ── Final decision ───────────────────────────────────────
        if decision_str == "APPROVE" and declarative_signals >= 2 and imperative_signals == 0:
            method = "declarative"
            primary_tool = "terraform"
            secondary_tool = "ansible"
        elif imperative_signals >= 3:
            method = "imperative"
            primary_tool = "azure_cli"
            secondary_tool = "ansible"
        elif has_constraints or (declarative_signals > 0 and imperative_signals > 0):
            method = "hybrid"
            primary_tool = "terraform"
            secondary_tool = "ansible"
        else:
            # Default safe choice
            method = "declarative"
            primary_tool = "terraform"
            secondary_tool = "ansible"
            reasoning.append("Default: declarative Terraform + Ansible")

        # ── Estimate required Azure resources ───────────────────
        resources = self._estimate_resources(constraints, ir_metrics)

        strat_confidence = min(confidence * 0.9, 0.95)

        logger.info(
            "Strategy decision for %s: method=%s tool=%s (confidence=%.2f)",
            task_id, method, primary_tool, strat_confidence,
        )

        return StrategyDecision(
            method=method,
            primary_tool=primary_tool,
            secondary_tool=secondary_tool,
            reasoning=reasoning,
            confidence=strat_confidence,
            estimated_resources=resources,
            constraints_applied=constraints,
            task_id=task_id,
            decided_at=time.time(),
        )

    def _estimate_resources(self, constraints: List[str], ir_metrics: Dict) -> List[str]:
        """Estimate Azure resources needed based on constraints and metrics."""
        resources = [
            "azurerm_resource_group",
            "azurerm_virtual_network",
            "azurerm_subnet",
            "azurerm_network_security_group",
            "azurerm_container_group",
        ]
        if "network_isolation" in constraints:
            resources.append("azurerm_private_endpoint")
            resources.append("azurerm_private_dns_zone")
        if "sandboxed_execution" in constraints:
            resources.append("azurerm_container_registry")
        if "monitoring_required" in constraints:
            resources.append("azurerm_log_analytics_workspace")
            resources.append("azurerm_monitor_activity_log_alert")
        if ir_metrics.get("network_call_count", 0) > 0:
            resources.append("azurerm_application_gateway")
        return resources