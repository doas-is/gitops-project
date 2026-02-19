"""
Policy Engine / Trial Agent

Decision engine for approving/rejecting code analysis results.

Decision modes:
  1. Declarative: Rule-based, deterministic
  2. Iterative: Multi-pass reasoning with increasing detail
  3. HITL Escalation: Human review when confidence below threshold

No access to raw code, AST, or IR.
Operates solely on RiskAssessment + structured metrics.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from config.azure_config import AGENT_CONFIG
from src.schemas.a2a_schemas import (
    AgentRole, HITLRequest, HITLResponse, MessageType,
    PolicyConstraint, PolicyDecision, RiskAssessment, create_header,
)

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    rule_id: str
    name: str
    condition: str  # Human description
    severity: str  # "critical", "high", "medium", "low"
    auto_reject: bool = False  # If True, triggers immediate rejection
    generates_constraint: Optional[str] = None

    def evaluate(self, assessment: RiskAssessment) -> Tuple[bool, str]:
        """Returns (triggered, reason)."""
        raise NotImplementedError


@dataclass
class AggregateRiskRule(PolicyRule):
    threshold: float = 0.85

    def evaluate(self, assessment: RiskAssessment) -> Tuple[bool, str]:
        if assessment.aggregate_risk >= self.threshold:
            return True, f"Aggregate risk {assessment.aggregate_risk:.2f} >= {self.threshold}"
        return False, ""


@dataclass
class HighRiskFileCountRule(PolicyRule):
    max_high_risk_files: int = 3

    def evaluate(self, assessment: RiskAssessment) -> Tuple[bool, str]:
        if assessment.high_risk_file_count > self.max_high_risk_files:
            return True, f"{assessment.high_risk_file_count} high-risk files exceed limit {self.max_high_risk_files}"
        return False, ""


@dataclass
class PrivilegedAPIRule(PolicyRule):
    max_privileged_apis: int = 10

    def evaluate(self, assessment: RiskAssessment) -> Tuple[bool, str]:
        if assessment.privileged_api_count > self.max_privileged_apis:
            return True, f"Privileged API count {assessment.privileged_api_count} exceeds {self.max_privileged_apis}"
        return False, ""


@dataclass
class AnomalousPatternRule(PolicyRule):
    max_patterns: int = 5

    def evaluate(self, assessment: RiskAssessment) -> Tuple[bool, str]:
        if assessment.anomalous_pattern_count > self.max_patterns:
            return True, f"{assessment.anomalous_pattern_count} anomalous patterns detected"
        return False, ""


@dataclass
class NetworkDynamicCombinationRule(PolicyRule):
    """High-risk: code with both network access and dynamic evaluation."""

    def evaluate(self, assessment: RiskAssessment) -> Tuple[bool, str]:
        for score in assessment.file_scores:
            has_network = "PATTERN_NETWORK_DYNAMIC" in score.flagged_patterns
            has_eval = "PATTERN_DYNAMIC_CODE" in score.flagged_patterns
            if has_network or has_eval:
                return True, "Network+dynamic-eval combination detected"
        return False, ""


# Default policy ruleset
DEFAULT_RULES: List[PolicyRule] = [
    AggregateRiskRule(
        rule_id="R001",
        name="AggregateRiskThreshold",
        condition="Aggregate risk score >= 0.85",
        severity="critical",
        auto_reject=True,
        threshold=0.85,
    ),
    AggregateRiskRule(
        rule_id="R002",
        name="ElevatedRiskThreshold",
        condition="Aggregate risk score >= 0.60",
        severity="high",
        auto_reject=False,
        generates_constraint="network_isolation",
        threshold=0.60,
    ),
    HighRiskFileCountRule(
        rule_id="R003",
        name="HighRiskFileCount",
        condition="More than 3 high-risk files",
        severity="high",
        auto_reject=False,
        generates_constraint="sandboxed_execution",
        max_high_risk_files=3,
    ),
    PrivilegedAPIRule(
        rule_id="R004",
        name="PrivilegedAPIUsage",
        condition="More than 10 privilege-sensitive API calls",
        severity="high",
        auto_reject=False,
        generates_constraint="privilege_restriction",
        max_privileged_apis=10,
    ),
    AnomalousPatternRule(
        rule_id="R005",
        name="AnomalousPatternDensity",
        condition="More than 5 anomalous structural patterns",
        severity="medium",
        auto_reject=False,
        generates_constraint="monitoring_required",
        max_patterns=5,
    ),
    NetworkDynamicCombinationRule(
        rule_id="R006",
        name="NetworkDynamicCombination",
        condition="Network access combined with dynamic code evaluation",
        severity="critical",
        auto_reject=True,
    ),
]

# Constraint templates
CONSTRAINT_TEMPLATES: Dict[str, PolicyConstraint] = {
    "network_isolation": PolicyConstraint(
        constraint_id="C001",
        constraint_type="network_isolation",
        severity="mandatory",
        description="Isolate application network access to approved endpoints only",
        terraform_snippet="""
resource "azurerm_network_security_group" "isolated" {
  name                = "isolated-nsg"
  location            = var.location
  resource_group_name = var.resource_group
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}""",
    ),
    "sandboxed_execution": PolicyConstraint(
        constraint_id="C002",
        constraint_type="sandboxed_execution",
        severity="mandatory",
        description="Execute in isolated sandbox with no external dependencies",
        terraform_snippet="""
resource "azurerm_container_group" "sandboxed" {
  name                = "sandboxed-app"
  location            = var.location
  resource_group_name = var.resource_group
  os_type             = "Linux"
  restart_policy      = "Never"
  container {
    name   = "app"
    image  = var.app_image
    cpu    = "0.5"
    memory = "1.5"
    security_context {
      allow_privilege_escalation = false
      read_only_root_filesystem  = true
      run_as_non_root            = true
    }
  }
}""",
    ),
    "privilege_restriction": PolicyConstraint(
        constraint_id="C003",
        constraint_type="privilege_restriction",
        severity="mandatory",
        description="Run with minimal RBAC permissions, no elevated roles",
        terraform_snippet="""
resource "azurerm_role_assignment" "minimal" {
  scope                = var.scope
  role_definition_name = "Reader"
  principal_id         = var.principal_id
}""",
    ),
    "monitoring_required": PolicyConstraint(
        constraint_id="C004",
        constraint_type="monitoring",
        severity="recommended",
        description="Enhanced monitoring and alerting required",
        terraform_snippet="""
resource "azurerm_monitor_activity_log_alert" "anomaly" {
  name                = "anomaly-alert"
  resource_group_name = var.resource_group
  scopes              = [var.resource_id]
  criteria {
    category = "Security"
    level    = "Warning"
  }
}""",
    ),
}


class PolicyEngine:
    """
    Policy decision engine.
    Operates on RiskAssessment only - no code access.
    """

    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        hitl_threshold: float = AGENT_CONFIG.hitl_escalation_threshold,
    ) -> None:
        self.rules = rules or DEFAULT_RULES
        self.hitl_threshold = hitl_threshold
        self._pending_hitl: Dict[str, HITLRequest] = {}
        self._hitl_responses: asyncio.Queue = asyncio.Queue()
        self._stats = {
            "decisions_made": 0,
            "approved": 0,
            "rejected": 0,
            "hitl_escalated": 0,
        }

    def evaluate(self, assessment: RiskAssessment) -> PolicyDecision:
        """
        Evaluate risk assessment against policy rules.
        Returns PolicyDecision.
        """
        triggered_rules = []
        constraints = []
        mitigations = []
        should_reject = False
        hitl_required = False
        hitl_reason = None

        # Pass 1: Evaluate all rules
        for rule in self.rules:
            triggered, reason = rule.evaluate(assessment)
            if triggered:
                triggered_rules.append((rule, reason))
                if rule.auto_reject:
                    should_reject = True
                if rule.generates_constraint and rule.generates_constraint in CONSTRAINT_TEMPLATES:
                    constraint = CONSTRAINT_TEMPLATES[rule.generates_constraint]
                    if constraint not in constraints:
                        constraints.append(constraint)
                mitigations.append(f"[{rule.rule_id}] {reason}")

        # Pass 2: Confidence assessment
        confidence = self._compute_confidence(assessment, triggered_rules)

        # Pass 3: HITL escalation check
        if (not should_reject
                and confidence < self.hitl_threshold
                and len(triggered_rules) > 0):
            hitl_required = True
            hitl_reason = f"Confidence {confidence:.2f} below threshold {self.hitl_threshold:.2f}"

        # Determine decision
        if should_reject:
            decision = "REJECT"
        elif hitl_required:
            decision = "APPROVE_WITH_CONSTRAINTS"  # Provisional until HITL
        elif len(triggered_rules) > 0:
            decision = "APPROVE_WITH_CONSTRAINTS"
        else:
            decision = "APPROVE"

        # Build risk summary (no code references)
        risk_summary = self._build_risk_summary(assessment, triggered_rules, decision)

        header = create_header(
            MessageType.POLICY_DECISION,
            AgentRole.POLICY_ENGINE,
            AgentRole.IAC_GENERATOR,
            assessment.task_id,
        )

        self._stats["decisions_made"] += 1
        self._stats[{"APPROVE": "approved", "REJECT": "rejected"}.get(decision, "approved")] += 1
        if hitl_required:
            self._stats["hitl_escalated"] += 1

        return PolicyDecision(
            header=header,
            task_id=assessment.task_id,
            decision=decision,
            confidence=confidence,
            risk_summary=risk_summary,
            constraints=constraints,
            required_mitigations=mitigations,
            rules_evaluated=len(self.rules),
            rules_triggered=len(triggered_rules),
            hitl_required=hitl_required,
            hitl_reason=hitl_reason,
        )

    def _compute_confidence(
        self,
        assessment: RiskAssessment,
        triggered_rules: List[Tuple],
    ) -> float:
        """Compute decision confidence score."""
        if not assessment.file_scores:
            return 0.5

        # Base confidence from ML model confidence scores
        avg_ml_confidence = sum(s.confidence for s in assessment.file_scores) / len(assessment.file_scores)

        # More triggered rules = more certainty (either clear approve or clear reject)
        rule_certainty = min(len(triggered_rules) * 0.15, 0.3)

        # High aggregate risk → higher confidence in assessment
        risk_certainty = assessment.aggregate_risk * 0.2

        confidence = min(avg_ml_confidence + rule_certainty + risk_certainty, 0.98)
        return confidence

    def _build_risk_summary(
        self,
        assessment: RiskAssessment,
        triggered_rules: List[Tuple],
        decision: str,
    ) -> str:
        """Build human-readable risk summary without code references."""
        lines = [
            f"Decision: {decision}",
            f"Aggregate Risk: {assessment.aggregate_risk:.2%}",
            f"Files Analyzed: {assessment.total_files}",
            f"High-Risk Files: {assessment.high_risk_file_count}",
            f"Rules Triggered: {len(triggered_rules)}/{len(self.rules)}",
        ]
        if triggered_rules:
            lines.append("Triggered Rules:")
            for rule, reason in triggered_rules:
                lines.append(f"  [{rule.severity.upper()}] {rule.rule_id}: {reason}")
        return "\n".join(lines)

    def create_hitl_request(
        self, assessment: RiskAssessment, reason: str
    ) -> HITLRequest:
        """Create HITL escalation request."""
        header = create_header(
            MessageType.HITL_REQUEST,
            AgentRole.POLICY_ENGINE,
            AgentRole.HITL_ESCALATION,
            assessment.task_id,
        )

        # Collect all unique flagged patterns
        all_patterns = set()
        for score in assessment.file_scores:
            all_patterns.update(score.flagged_patterns)

        request = HITLRequest(
            header=header,
            task_id=assessment.task_id,
            reason=reason,
            risk_assessment_summary=(
                f"Aggregate risk: {assessment.aggregate_risk:.2%}, "
                f"{assessment.high_risk_file_count}/{assessment.total_files} high-risk files, "
                f"{assessment.anomalous_pattern_count} anomalous patterns"
            ),
            aggregate_risk=assessment.aggregate_risk,
            flagged_patterns=list(all_patterns),
            recommended_action="REJECT" if assessment.aggregate_risk > 0.7 else "APPROVE_WITH_CONSTRAINTS",
            expires_at=time.time() + 3600,  # 1 hour expiry
        )

        self._pending_hitl[request.header.message_id] = request
        return request

    async def wait_for_hitl(
        self, request_id: str, timeout: float = 3600.0
    ) -> Optional[HITLResponse]:
        """Wait for human operator decision."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                response = await asyncio.wait_for(
                    self._hitl_responses.get(),
                    timeout=min(30.0, deadline - time.time()),
                )
                if response.request_id == request_id:
                    return response
                # Re-queue if for different request
                await self._hitl_responses.put(response)
            except asyncio.TimeoutError:
                continue
        return None

    async def submit_hitl_response(self, response: HITLResponse) -> None:
        """Submit human operator decision."""
        await self._hitl_responses.put(response)

    def get_stats(self) -> dict:
        return dict(self._stats)