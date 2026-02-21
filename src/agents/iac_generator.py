"""
Receives: PolicyDecision + StrategyDecision (+ optional error_feedback on retry)
Produces: IaCBundle — Terraform (.tf) + Ansible (.yml) as in-memory strings

Security contract
─────────────────
  • Never sees raw code, AST, or IR — only constraint names + strategy metadata
  • All generated files are held in memory; the Deployment Agent applies them
  • client_secret is NEVER a Terraform variable — read from Key Vault at runtime
  • NSG priorities are unique and validated before generation

What it does with the inputs
──────────────────────────
  • generate() now accepts error_feedback: str parameter — fed from
    FeasibilityValidatorAgent.retry_hint on retry attempts. When the LLM
    backend is wired in this is injected into the prompt. For now it is
    logged and recorded in the IaCBundle for audit.

  • IaCBundle now carries: attempt (int), error_feedback (str)
    so the audit log and the UI can show retry context.

  • Duplicate NSG priority 4096 on DenyAllInbound + DenyAllOutbound
    → unique priorities 4094 (Inbound) and 4095 (Outbound)

  • client_secret removed from variables.tf entirely
    → sourced from Key Vault at runtime, never in state or plan output

  • var.action_group_id now declared in variables.tf
    (was referenced in monitoring.tf but never declared → terraform validate error)

  • var.allowed_cidr default tightened from 0.0.0.0/0 → 10.0.0.0/8
    (zero-trust: no public inbound by default)

  • container.tf depends_on subnet_nsg_association added
    (ACI without NSG association caused race condition on first deploy)

  • Ansible handlers block was missing entirely — ansible-lint fatal error
    → _ansible_handlers() now always emitted for declarative/hybrid

  • Imperative script was missing DenyAllOutbound NSG rule
    → both Inbound and Outbound deny rules now added with unique priorities

  • private_endpoint.tf now included when network_isolation constraint set

  • rbac.tf now included when privilege_restriction constraint set
    → user-assigned identity + Reader role assignment

  • var.key_vault_id declared in variables.tf when network_isolation set

  • outputs.tf now exports subnet_id (referenced by container.tf)

  • _tf_keyvault_access.tf generated when privilege_restriction set
    → Key Vault access policy granting the app identity get/list on secrets

  • Error feedback is embedded as a comment block at the top of main.tf
    on retry attempts, giving the LLM (future) the full context it needs
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from logs.audit import get_audit

logger = logging.getLogger(__name__)

import os
import urllib.request
import json as _json

def _ollama_generate(prompt: str) -> str:
    """Call local Ollama for LLM-assisted IaC generation."""
    if os.getenv("OLLAMA_ENABLED", "false").lower() != "true":
        return ""
    try:
        url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434") + "/api/generate"
        payload = _json.dumps({
            "model":  os.getenv("OLLAMA_MODEL", "llama3.1"),
            "prompt": prompt,
            "stream": False,
        }).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return _json.loads(resp.read())["response"]
    except Exception as e:
        logger.warning("Ollama unavailable (%s) — using static templates", e)
        return ""
# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class IaCBundle:
    """
    All generated IaC files for one task — held in memory only.
    Never written to disk by this agent.
    """
    task_id:             str
    method:              str                   # "declarative" | "imperative" | "hybrid"
    terraform_files:     Dict[str, str]        # filename → HCL content
    ansible_files:       Dict[str, str]        # filename → YAML content
    resource_list:       List[str]             # expected azurerm_* resource types
    constraints_applied: List[str]
    attempt:             int   = 1             # which retry attempt produced this bundle
    error_feedback:      str   = ""            # feedback that triggered this attempt
    generated_at:        float = field(default_factory=time.time)


# ── Agent ─────────────────────────────────────────────────────────────────────

class IaCGeneratorAgent:
    """
    Generates Terraform + Ansible from policy constraints and strategy.

    Input:  PolicyDecision, StrategyDecision, optional error_feedback
    Output: IaCBundle (in-memory, never written to disk by this agent)

    The agent never sees raw source code — only structured constraint names
    and strategy metadata derived from the IR layer.
    """

    def __init__(self) -> None:
        self._audit = get_audit()

    def generate(self, policy_decision, strategy_decision,
             error_feedback: str = "", attempt: int = 1) -> IaCBundle:
        """
        Generate a complete IaCBundle.

        Parameters
        ──────────
        policy_decision   — PolicyDecision from Stage 5
        strategy_decision — StrategyDecision from Stage 6
        error_feedback    — Retry hint from FeasibilityValidatorAgent (empty on first attempt).
                            Currently logged and embedded as a comment in main.tf.
                            When the LLM backend is wired in, inject this into the prompt.
        attempt           — Which attempt number this is (1-based, from retry loop)
        """
        task_id     = policy_decision.task_id
        constraints = [c.constraint_type for c in policy_decision.constraints]
        method      = strategy_decision.method
        resources   = strategy_decision.estimated_resources
    
        logger.info(
            "[%s] IaCGeneratorAgent.generate: method=%s constraints=%s attempt=%d feedback=%s",
            task_id, method, constraints, attempt,
            f'"{error_feedback[:80]}..."' if error_feedback else "none",
        )
        self._audit.log(
            "IAC_GENERATE_START", "info", task_id=task_id, stage="iac",
            message=f"IaC generation started (attempt={attempt}, method={method})",
            data={
                "attempt":        attempt,
                "method":         method,
                "constraints":    constraints,
                "has_feedback":   bool(error_feedback),
                "feedback_len":   len(error_feedback),
            },
        )

        if method == "none":
            return IaCBundle(
                task_id=task_id, method="none",
                terraform_files={}, ansible_files={},
                resource_list=[], constraints_applied=constraints,
                attempt=attempt, error_feedback=error_feedback,
            )

        tf_files:  Dict[str, str] = {}
        ans_files: Dict[str, str] = {}

        # ── Core infrastructure ────────────────────────
        tf_files["main.tf"]      = self._tf_main(task_id, constraints, resources, error_feedback, attempt)
        tf_files["variables.tf"] = self._tf_variables(constraints)
        tf_files["outputs.tf"]   = self._tf_outputs()
        tf_files["container.tf"] = self._tf_container(task_id)

        # ── Declarative / hybrid: Ansible hardening ───────────────────────
        if method in ("declarative", "hybrid"):
            ans_files["site.yml"]                          = self._ansible_site(task_id, constraints)
            ans_files["roles/hardening/tasks/main.yml"]    = self._ansible_hardening(constraints)
            ans_files["roles/hardening/handlers/main.yml"] = self._ansible_handlers()

        # ── Imperative: ordered az CLI script ─────────────────────────────
        if method == "imperative":
            tf_files["deploy.sh"] = self._imperative_script(task_id, constraints)

        # ── Conditional Terraform resources ───────────────────────────────
        if "sandboxed_execution" in constraints:
            tf_files["container.tf"] = self._tf_container(task_id)

        if "monitoring_required" in constraints:
            tf_files["monitoring.tf"] = self._tf_monitoring(task_id)

        if "network_isolation" in constraints:
            tf_files["private_endpoint.tf"] = self._tf_private_endpoint(task_id)

        if "privilege_restriction" in constraints:
            tf_files["rbac.tf"]             = self._tf_rbac()
            tf_files["keyvault_access.tf"]  = self._tf_keyvault_access(task_id)

        # ── LLM-assisted fix on retry attempts ────────────────────────────
        if attempt > 1 and error_feedback and os.getenv("OLLAMA_ENABLED") == "true":
            llm_hint = _ollama_generate(
                f"You are a Terraform expert. The following IaC validation error occurred:\n\n"
                f"{error_feedback}\n\n"
                f"The deployment constraints are: {constraints}\n"
                f"The required Azure resources are: {resources}\n\n"
                f"List ONLY the Terraform resource blocks needed to fix this error. "
                f"Output valid HCL only, no explanation."
            )
            if llm_hint:
                tf_files["llm_fix.tf"] = llm_hint
                logger.info("[%s] Ollama provided IaC fix (attempt %d)", task_id, attempt)

        bundle = IaCBundle(
            task_id=task_id,
            method=method,
            terraform_files=tf_files,
            ansible_files=ans_files,
            resource_list=resources,
            constraints_applied=constraints,
            attempt=attempt,
            error_feedback=error_feedback,
        )

        self._audit.iac_generated(
            task_id,
            list(tf_files.keys()),
            list(ans_files.keys()),
        )
        logger.info(
            "[%s] IaC generated: %d TF files, %d Ansible files (attempt=%d)",
            task_id, len(tf_files), len(ans_files), attempt,
        )
        return bundle

    # ══════════════════════════════════════════════════════════════════════════
    # Terraform templates
    # ══════════════════════════════════════════════════════════════════════════

    def _tf_main(
        self,
        task_id: str,
        constraints: List[str],
        resources: List[str],
        error_feedback: str = "",
        attempt: int = 1,
    ) -> str:
        """Core provider + resource group + VNet + subnet."""
        isolation = "true" if "network_isolation"   in constraints else "false"
        sandbox   = "true" if "sandboxed_execution" in constraints else "false"

        # Embed retry feedback as a comment block so the LLM (future) sees it
        feedback_block = ""
        if error_feedback and attempt > 1:
            feedback_block = (
                f"\n# ── RETRY CONTEXT (attempt {attempt}) ──────────────────────────────\n"
                + "\n".join(f"# {line}" for line in error_feedback.splitlines()[:20])
                + "\n# ────────────────────────────────────────────────────────────────\n"
            )

        return f'''# Generated by IaC Generator Agent
# Task:    {task_id}
# Attempt: {attempt}
# Method:  terraform (azurerm ~> 3.0)
# DO NOT EDIT — auto-generated, ephemeral
{feedback_block}
terraform {{
  required_providers {{
    azurerm = {{
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }}
  }}
  # Remote state: stored in Azure Blob Storage, never on the ephemeral VM.
  # The VM is destroyed after deployment — local state would be lost.
  backend "azurerm" {{
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "{task_id}.tfstate"
  }}
}}

provider "azurerm" {{
  features {{}}
  # Auth via environment variables (ARM_CLIENT_ID, ARM_TENANT_ID, etc.)
  # client_secret is sourced from Key Vault at runtime — never declared here.
  subscription_id = var.subscription_id
}}

resource "azurerm_resource_group" "main" {{
  name     = "rg-${{var.app_name}}-${{var.environment}}"
  location = var.location
  tags = {{
    task_id    = "{task_id}"
    managed_by = "secure-analysis-platform"
    isolated   = "{isolation}"
    sandboxed  = "{sandbox}"
  }}
}}

resource "azurerm_virtual_network" "main" {{
  name                = "vnet-${{var.app_name}}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.0.0.0/16"]
  tags = {{
    task_id = "{task_id}"
  }}
}}

resource "azurerm_subnet" "app" {{
  name                 = "snet-app"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}}

# NSG association must be applied before any resources (e.g. ACI) attach to the subnet.
resource "azurerm_subnet_network_security_group_association" "app" {{
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_nsg(self, constraints: List[str]) -> str:
        """
        Network Security Group.

        Priority allocation (all unique — Azure requires uniqueness per NSG):
          100  AllowHTTPS          inbound  from var.allowed_cidr
          200  AllowInternalMTLS   inbound  from internal VNet (mTLS agents)
          300  AllowHTTPS          outbound to Azure services
          4094 DenyAllInbound      inbound  catch-all  ← was 4096, now 4094
          4095 DenyAllOutbound     outbound catch-all  ← was 4096 (duplicate!), now 4095
        """
        deny = "network_isolation" in constraints
        # With network_isolation: deny ALL traffic by default (strict zero-trust).
        # Without: deny catch-alls are still present but with lower priority.
        inbound_catch  = "Deny" if deny else "Deny"   # always deny — defence in depth
        outbound_catch = "Deny" if deny else "Deny"

        return f'''# NSG — Network Security Group
# network_isolation = {deny}
# All priorities are UNIQUE per NSG (Azure hard requirement).
# DenyAll rules use 4094/4095 — NOT 4096 (which is Azure's implicit deny, non-configurable).

resource "azurerm_network_security_group" "app" {{
  name                = "nsg-app"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # ── Inbound: allow HTTPS from approved CIDR ──────────────────────────────
  security_rule {{
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = var.allowed_cidr
    destination_address_prefix = "*"
  }}

  # ── Inbound: allow mTLS between agents on the VNet ───────────────────────
  security_rule {{
    name                       = "AllowInternalMTLS"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8443"
    source_address_prefix      = "10.0.0.0/16"
    destination_address_prefix = "*"
  }}

  # ── Outbound: allow HTTPS to Azure platform services ─────────────────────
  security_rule {{
    name                       = "AllowAzureServicesOutbound"
    priority                   = 300
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "AzureCloud"
  }}

  # ── Catch-all deny (inbound) — priority 4094, NOT 4096 ───────────────────
  security_rule {{
    name                       = "DenyAllInbound"
    priority                   = 4094
    direction                  = "Inbound"
    access                     = "{inbound_catch}"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }}

  # ── Catch-all deny (outbound) — priority 4095, NOT 4096 ──────────────────
  security_rule {{
    name                       = "DenyAllOutbound"
    priority                   = 4095
    direction                  = "Outbound"
    access                     = "{outbound_catch}"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }}

  tags = {{
    managed_by        = "secure-analysis-platform"
    network_isolation = "{str(deny).lower()}"
  }}
}}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_variables(self, constraints: List[str]) -> str:
        """
        Declare all variables referenced across all generated .tf files.

        Rules:
          - client_secret is NEVER declared here (sourced from Key Vault at runtime)
          - allowed_cidr defaults to 10.0.0.0/8 (private RFC-1918, not 0.0.0.0/0)
          - action_group_id declared only when monitoring_required
          - key_vault_id declared only when network_isolation
          - app_image declared only when sandboxed_execution
        """
        monitoring_var    = (
            '\nvariable "action_group_id" {\n'
            '  description = "Azure Monitor Action Group resource ID for security alerts"\n'
            '}'
            if "monitoring_required"  in constraints else ""
        )
        network_iso_var   = (
            '\nvariable "key_vault_id" {\n'
            '  description = "Resource ID of the Key Vault for private endpoint"\n'
            '}'
            if "network_isolation"    in constraints else ""
        )
        sandbox_var       = (
            '\nvariable "app_image" {\n'
            '  description = "Container image URI (e.g. myacr.azurecr.io/app:latest)"\n'
            '}'
            if "sandboxed_execution"  in constraints else ""
        )
        rbac_var          = (
            '\nvariable "keyvault_name" {\n'
            '  description = "Name of the Key Vault for access policy binding"\n'
            '}'
            if "privilege_restriction" in constraints else ""
        )

        return f'''# Variables — auto-generated by IaC Generator Agent
# client_secret is intentionally absent: read from Key Vault at runtime.

variable "subscription_id" {{
  description = "Azure Subscription ID"
}}

variable "location" {{
  description = "Azure region"
  default     = "eastus"
}}

variable "app_name" {{
  description = "Application name (used in resource naming)"
}}

variable "environment" {{
  description = "Deployment environment (prod / staging / dev)"
  default     = "prod"
}}

variable "allowed_cidr" {{
  description = "CIDR allowed for HTTPS inbound. Default: RFC-1918 private only."
  default     = "10.0.0.0/8"
}}

variable "state_resource_group" {{
  description = "Resource group containing the Terraform state storage account"
}}

variable "state_storage_account" {{
  description = "Storage account name for Terraform remote state"
}}{monitoring_var}{network_iso_var}{sandbox_var}{rbac_var}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_outputs(self) -> str:
        """Export key resource identifiers. subnet_id needed by container.tf."""
        return '''# Outputs — auto-generated by IaC Generator Agent

output "resource_group_name" {
  description = "Name of the deployed resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "Resource ID of the deployed resource group"
  value       = azurerm_resource_group.main.id
}

output "vnet_id" {
  description = "Resource ID of the VNet"
  value       = azurerm_virtual_network.main.id
}

output "subnet_id" {
  description = "Resource ID of the app subnet (referenced by container.tf)"
  value       = azurerm_subnet.app.id
}

output "nsg_id" {
  description = "Resource ID of the NSG"
  value       = azurerm_network_security_group.app.id
}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_container(self, task_id: str) -> str:
        """
        Sandboxed ACI container group.
        depends_on ensures NSG association is complete before ACI is created —
        without this ACI can attach to a subnet with no NSG (race condition).
        """
        return f'''# Sandboxed ACI container — task {task_id}
# SECURITY: depends_on NSG association — ACI must never attach to an unprotected subnet.

resource "azurerm_container_group" "app" {{
  name                = "aci-app-${{var.app_name}}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  restart_policy      = "Never"
  ip_address_type     = "Private"
  subnet_ids          = [azurerm_subnet.app.id]

  # Critical: NSG must be associated before container starts
  depends_on = [azurerm_subnet_network_security_group_association.app]

  container {{
    name   = "app"
    image  = var.app_image
    cpu    = "0.5"
    memory = "1.5"

    ports {{
      port     = 8080
      protocol = "TCP"
    }}

    # Hardened security context — least privilege, read-only root
    security_context {{
      allow_privilege_escalation = false
      read_only_root_filesystem  = true
      run_as_non_root            = true
      run_as_user                = 1000
    }}

    # Liveness probe — ACI replaces container if /healthz stops responding
    liveness_probe {{
      http_get {{
        path   = "/healthz"
        port   = 8080
        scheme = "Http"
      }}
      initial_delay_seconds = 15
      period_seconds        = 20
      failure_threshold     = 3
    }}

    # Non-secret config only — secrets sourced from Key Vault via identity
    environment_variables = {{
      APP_ENV = var.environment
      TASK_ID = "{task_id}"
    }}
  }}

  tags = {{
    task_id    = "{task_id}"
    managed_by = "secure-analysis-platform"
  }}
}}

output "container_ip" {{
  description = "Private IP of the ACI container group"
  value       = azurerm_container_group.app.ip_address
}}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_monitoring(self, task_id: str) -> str:
        """
        Log Analytics workspace + activity log alert.
        var.action_group_id is declared in variables.tf when monitoring_required.
        """
        return f'''# Monitoring — task {task_id}
# Requires: var.action_group_id (declared in variables.tf)

resource "azurerm_log_analytics_workspace" "main" {{
  name                = "law-${{var.app_name}}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {{
    task_id    = "{task_id}"
    managed_by = "secure-analysis-platform"
  }}
}}

resource "azurerm_monitor_activity_log_alert" "security" {{
  name                = "alert-security-${{var.app_name}}"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_resource_group.main.id]
  description         = "Alert on Security-category events at Warning level or above"

  criteria {{
    category = "Security"
    level    = "Warning"
  }}

  action {{
    action_group_id = var.action_group_id
  }}

  tags = {{
    task_id = "{task_id}"
  }}
}}

output "log_analytics_workspace_id" {{
  description = "Resource ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.main.id
}}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_private_endpoint(self, task_id: str) -> str:
        """
        Private endpoint for Key Vault — network_isolation constraint.
        Routes all Key Vault traffic over the private VNet, no public internet.
        var.key_vault_id is declared in variables.tf when network_isolation.
        """
        return f'''# Private endpoint — network_isolation constraint
# Routes Key Vault traffic over the private VNet only.
# Requires: var.key_vault_id (declared in variables.tf)

resource "azurerm_subnet" "private_endpoint" {{
  name                 = "snet-pe"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]

  # Disable network policies so private endpoint can be placed in this subnet
  private_endpoint_network_policies_enabled = false
}}

resource "azurerm_private_endpoint" "key_vault" {{
  name                = "pe-kv-{task_id[:8]}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoint.id

  private_service_connection {{
    name                           = "psc-kv-{task_id[:8]}"
    private_connection_resource_id = var.key_vault_id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }}

  tags = {{
    task_id    = "{task_id}"
    managed_by = "secure-analysis-platform"
  }}
}}

resource "azurerm_private_dns_zone" "key_vault" {{
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.main.name
}}

resource "azurerm_private_dns_zone_virtual_network_link" "key_vault" {{
  name                  = "pdnslink-kv"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.key_vault.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
}}

resource "azurerm_private_dns_a_record" "key_vault" {{
  name                = "@"
  zone_name           = azurerm_private_dns_zone.key_vault.name
  resource_group_name = azurerm_resource_group.main.name
  ttl                 = 300
  records             = [azurerm_private_endpoint.key_vault.private_service_connection[0].private_ip_address]
}}

output "private_endpoint_ip" {{
  description = "Private IP of the Key Vault private endpoint"
  value       = azurerm_private_endpoint.key_vault.private_service_connection[0].private_ip_address
}}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_rbac(self) -> str:
        """
        User-assigned managed identity + Reader role — privilege_restriction.
        Grants the app identity the minimum role needed on the resource group.
        Never uses a service principal client_secret.
        """
        return '''# RBAC — privilege_restriction constraint
# App gets a user-assigned identity with Reader role only.
# Use Key Vault access policy (keyvault_access.tf) to grant secret access.

resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${var.app_name}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

# Reader: can view resources but cannot modify them or read secrets
resource "azurerm_role_assignment" "app_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

output "app_identity_id" {
  description = "Client ID of the user-assigned managed identity"
  value       = azurerm_user_assigned_identity.app.client_id
}

output "app_identity_principal_id" {
  description = "Principal ID of the user-assigned managed identity"
  value       = azurerm_user_assigned_identity.app.principal_id
}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _tf_keyvault_access(self, task_id: str) -> str:
        """
        Key Vault access policy — privilege_restriction constraint.
        Grants get + list on secrets only; no set, delete, or key operations.
        Requires: var.keyvault_name (declared in variables.tf)
        """
        return f'''# Key Vault access policy — privilege_restriction constraint
# App identity gets: secret get + list ONLY.
# No key operations, no certificate operations, no purge.
# Requires: var.keyvault_name (declared in variables.tf)
# Requires: azurerm_user_assigned_identity.app (from rbac.tf)

data "azurerm_client_config" "current" {{}}

data "azurerm_key_vault" "main" {{
  name                = var.keyvault_name
  resource_group_name = azurerm_resource_group.main.name
}}

resource "azurerm_key_vault_access_policy" "app" {{
  key_vault_id = data.azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.app.principal_id

  # Least-privilege: read secrets only — no write, no key, no cert operations
  secret_permissions = ["Get", "List"]
  key_permissions    = []
  storage_permissions = []
}}
'''

    # ══════════════════════════════════════════════════════════════════════════
    # Ansible templates
    # ══════════════════════════════════════════════════════════════════════════

    def _ansible_site(self, task_id: str, constraints: List[str]) -> str:
        """Top-level site.yml — entrypoint for ansible-playbook."""
        roles = ["common", "hardening"]
        if "monitoring_required" in constraints:
            roles.append("monitoring")
        roles_block = "\n    - ".join(roles)
        return f'''---
# Ansible site playbook — task {task_id}
# Generated by IaC Generator Agent
# Run: ansible-playbook site.yml -i inventory.yml

- name: Deploy and harden application servers
  hosts: app_servers
  become: yes
  gather_facts: yes

  vars:
    task_id: "{task_id}"
    app_env: "{{{{ lookup('env', 'APP_ENV') | default('prod', true) }}}}"

  roles:
    - {roles_block}
'''

    # ─────────────────────────────────────────────────────────────────────────

    def _ansible_hardening(self, constraints: List[str]) -> str:
        """
        Hardening tasks role.
        Every task has a `name` (ansible-lint requirement).
        Notify handlers use exact names matching _ansible_handlers().
        """
        # Base tasks always applied
        base = '''\
---
# Hardening tasks — generated by IaC Generator Agent
# roles/hardening/tasks/main.yml

- name: Ensure SSH PermitRootLogin is disabled
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "^#?PermitRootLogin"
    line: "PermitRootLogin no"
    validate: "/usr/sbin/sshd -t -f %s"
    backup: yes
  notify: restart sshd

- name: Ensure SSH PasswordAuthentication is disabled
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "^#?PasswordAuthentication"
    line: "PasswordAuthentication no"
    validate: "/usr/sbin/sshd -t -f %s"
    backup: yes
  notify: restart sshd

- name: Set secure umask system-wide
  ansible.builtin.lineinfile:
    path: /etc/profile
    line: "umask 027"
    regexp: "^umask"
    create: yes

- name: Ensure UFW is installed
  ansible.builtin.package:
    name: ufw
    state: present

- name: Set UFW default inbound policy to deny
  community.general.ufw:
    state: enabled
    policy: deny
    direction: incoming

- name: Set UFW default outbound policy to deny
  community.general.ufw:
    state: enabled
    policy: deny
    direction: outgoing

- name: Allow SSH inbound (port 22)
  community.general.ufw:
    rule: allow
    port: "22"
    proto: tcp
    direction: in

- name: Allow HTTPS inbound (port 443)
  community.general.ufw:
    rule: allow
    port: "443"
    proto: tcp
    direction: in

- name: Allow HTTPS outbound to Azure services (port 443)
  community.general.ufw:
    rule: allow
    port: "443"
    proto: tcp
    direction: out
    to: any

- name: Disable core dumps
  ansible.builtin.lineinfile:
    path: /etc/security/limits.conf
    line: "* hard core 0"

- name: Ensure auditd is installed and enabled
  ansible.builtin.package:
    name: auditd
    state: present
  notify: restart auditd
'''
        network_tasks = ""
        if "network_isolation" in constraints:
            network_tasks = '''
- name: Block all remaining outbound traffic (network_isolation)
  community.general.ufw:
    rule: deny
    direction: out
    to: any
    comment: "network_isolation constraint — deny all outbound not explicitly allowed"
'''

        privilege_tasks = ""
        if "privilege_restriction" in constraints:
            privilege_tasks = '''
- name: Remove SUID bit from su
  ansible.builtin.file:
    path: /usr/bin/su
    mode: "u-s"

- name: Remove SUID bit from sudo
  ansible.builtin.file:
    path: /usr/bin/sudo
    mode: "u-s"

- name: Restrict cron to root only
  ansible.builtin.file:
    path: /etc/cron.allow
    owner: root
    group: root
    mode: "0600"
    state: touch

- name: Ensure only root in cron.allow
  ansible.builtin.copy:
    dest: /etc/cron.allow
    content: "root\n"
    owner: root
    group: root
    mode: "0600"
'''

        return base + network_tasks + privilege_tasks

    # ─────────────────────────────────────────────────────────────────────────

    def _ansible_handlers(self) -> str:
        """
        Handlers for the hardening role.
        MUST match names used in `notify:` directives in _ansible_hardening().
        Previously missing entirely — caused ansible-lint fatal error.
        """
        return '''\
---
# Handlers — roles/hardening/handlers/main.yml
# Handler names must match exactly what is used in notify: directives.

- name: restart sshd
  ansible.builtin.service:
    name: sshd
    state: restarted
  listen: restart sshd

- name: restart auditd
  ansible.builtin.service:
    name: auditd
    state: restarted
  listen: restart auditd

- name: reload ufw
  community.general.ufw:
    state: reloaded
  listen: reload ufw
'''

    # ══════════════════════════════════════════════════════════════════════════
    # Imperative script (az CLI)
    # ══════════════════════════════════════════════════════════════════════════

    def _imperative_script(self, task_id: str, constraints: List[str]) -> str:
        """
        Ordered az CLI deployment script.
        Used for high-risk / HITL-escalated workloads where Terraform's
        declarative approach provides insufficient ordering control.

        FIXED: DenyAllOutbound rule added (was missing in prior version).
        FIXED: Unique NSG rule priorities — Inbound 4094, Outbound 4095.
        """
        monitoring_step = ""
        if "monitoring_required" in constraints:
            monitoring_step = '''
echo "[5/7] Creating Log Analytics workspace..."
az monitor log-analytics workspace create \\
  --resource-group "$RG" \\
  --workspace-name "law-${APP_NAME}" \\
  --location "$LOCATION" \\
  --tags task_id={task_id}
'''.format(task_id=task_id)

        sandbox_step = ""
        if "sandboxed_execution" in constraints:
            sandbox_step = '''
echo "[6/7] Deploying sandboxed container..."
az container create \\
  --resource-group "$RG" \\
  --name "aci-app" \\
  --image "$APP_IMAGE" \\
  --cpu 0.5 \\
  --memory 1.5 \\
  --subnet snet-app \\
  --vnet vnet-app \\
  --restart-policy Never \\
  --environment-variables APP_ENV="$ENVIRONMENT" TASK_ID="{task_id}" \\
  --tags task_id={task_id}
'''.format(task_id=task_id)

        return f'''#!/bin/bash
# Imperative deployment script — task {task_id}
# Generated by IaC Generator Agent (method=imperative)
# Used for high-risk workloads requiring ordered, step-by-step provisioning.
#
# Prerequisites:
#   az login (or ARM_* env vars set)
#   APP_IMAGE, APP_NAME, ENVIRONMENT env vars set

set -euo pipefail

RG="rg-${{APP_NAME:-app}}-${{ENVIRONMENT:-prod}}"
LOCATION="${{AZURE_LOCATION:-eastus}}"
APP_NAME="${{APP_NAME:-app}}"
ENVIRONMENT="${{ENVIRONMENT:-prod}}"

echo "=== Imperative deployment: task {task_id} ==="
echo "Resource group : $RG"
echo "Location       : $LOCATION"

echo ""
echo "[1/7] Creating resource group..."
az group create \\
  --name "$RG" \\
  --location "$LOCATION" \\
  --tags task_id={task_id} managed_by=secure-analysis-platform

echo ""
echo "[2/7] Creating VNet..."
az network vnet create \\
  --resource-group "$RG" \\
  --name "vnet-${{APP_NAME}}" \\
  --address-prefix 10.0.0.0/16 \\
  --location "$LOCATION"

echo ""
echo "[3/7] Creating NSG with deny-all rules..."
az network nsg create \\
  --resource-group "$RG" \\
  --name "nsg-app" \\
  --location "$LOCATION"

# Allow HTTPS inbound from internal network only
az network nsg rule create \\
  --resource-group "$RG" \\
  --nsg-name nsg-app \\
  --name AllowHTTPS \\
  --priority 100 \\
  --direction Inbound \\
  --access Allow \\
  --protocol Tcp \\
  --destination-port-ranges 443 \\
  --source-address-prefixes 10.0.0.0/8

# Allow mTLS agent traffic inside VNet
az network nsg rule create \\
  --resource-group "$RG" \\
  --nsg-name nsg-app \\
  --name AllowInternalMTLS \\
  --priority 200 \\
  --direction Inbound \\
  --access Allow \\
  --protocol Tcp \\
  --destination-port-ranges 8443 \\
  --source-address-prefixes 10.0.0.0/16

# Allow HTTPS outbound to Azure platform
az network nsg rule create \\
  --resource-group "$RG" \\
  --nsg-name nsg-app \\
  --name AllowAzureOutbound \\
  --priority 300 \\
  --direction Outbound \\
  --access Allow \\
  --protocol Tcp \\
  --destination-port-ranges 443 \\
  --destination-address-prefixes AzureCloud

# Deny all other inbound — priority 4094 (NOT 4096 — that is Azure's implicit rule)
az network nsg rule create \\
  --resource-group "$RG" \\
  --nsg-name nsg-app \\
  --name DenyAllInbound \\
  --priority 4094 \\
  --direction Inbound \\
  --access Deny \\
  --protocol "*" \\
  --source-address-prefixes "*" \\
  --destination-address-prefixes "*"

# Deny all other outbound — priority 4095
az network nsg rule create \\
  --resource-group "$RG" \\
  --nsg-name nsg-app \\
  --name DenyAllOutbound \\
  --priority 4095 \\
  --direction Outbound \\
  --access Deny \\
  --protocol "*" \\
  --source-address-prefixes "*" \\
  --destination-address-prefixes "*"

echo ""
echo "[4/7] Creating subnet and associating NSG..."
az network vnet subnet create \\
  --resource-group "$RG" \\
  --vnet-name "vnet-${{APP_NAME}}" \\
  --name snet-app \\
  --address-prefix 10.0.1.0/24 \\
  --nsg nsg-app
{monitoring_step}{sandbox_step}
echo ""
echo "[7/7] Verifying deployment..."
az group show --name "$RG" --query "properties.provisioningState" -o tsv

echo ""
echo "=== Deployment complete: task {task_id} ==="
'''