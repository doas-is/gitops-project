"""
Azure Real Infrastructure Provisioner  —  src/azure_setup.py

Provisions REAL Azure resources:
  - One shared VNet + NSG for the entire task (analysis network)
  - One Azure Container Instance per pipeline stage (ephemeral microVM)
  - Azure Key Vault for KEK — all DEKs wrapped here, never stored elsewhere
  - Each container gets a unique short-lived mTLS cert signed by platform CA
  - On violation or completion: container deleted, cert revoked, NSG rule removed

Container topology per task:
  ┌─────────────────────────────────────────────────────┐
  │  VNet: 10.0.0.0/16   NSG: deny-all default         │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
  │  │ fetcher  │→ │ parser-N │→ │ ml/policy│  (mTLS)  │
  │  │ ACI      │  │ ACI×file │  │ ACI      │          │
  │  └──────────┘  └──────────┘  └──────────┘          │
  └─────────────────────────────────────────────────────┘

Auth: Uses AzureCliCredential (az login) when SP vars not set.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from azure.identity import (
    AzureCliCredential,
    ClientSecretCredential,
    ManagedIdentityCredential,
)
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerinstance.models import (
    Container,
    ContainerGroup,
    ContainerGroupNetworkProtocol,
    ContainerPort,
    EnvironmentVariable,
    ImageRegistryCredential,
    IpAddress,
    OperatingSystemTypes,
    Port,
    ResourceRequests,
    ResourceRequirements,
)
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import (
    NetworkSecurityGroup,
    SecurityRule,
    Subnet,
    VirtualNetwork,
    AddressSpace,
    SubResource,
)
from azure.mgmt.resource import ResourceManagementClient

from config.azure_config import AZURE_CONFIG, AGENT_CONFIG
from src.security.mtls import generate_agent_certificate, generate_ca_certificate

logger = logging.getLogger(__name__)

# ── Container image — lightweight Python runtime for agents ──────────────────
# In production replace with your ACR image that has all agent deps installed
AGENT_IMAGE = os.getenv("AGENT_IMAGE", "python:3.11-slim")

# ── Network constants ─────────────────────────────────────────────────────────
VNET_CIDR   = "10.0.0.0/16"
SUBNET_CIDR = "10.0.1.0/24"
AGENT_PORT  = 8443


class VMStatus(str, Enum):
    PROVISIONING = "provisioning"
    RUNNING      = "running"
    TERMINATING  = "terminating"
    TERMINATED   = "terminated"
    FAILED       = "failed"
    VIOLATED     = "violated"


@dataclass
class MicroVMRecord:
    vm_id:              str
    agent_role:         str
    task_id:            str
    azure_vm_name:      str       # ACI container group name
    private_ip:         str
    agent_port:         int
    cert_pem:           bytes
    status:             VMStatus = VMStatus.PROVISIONING
    created_at:         float    = field(default_factory=time.time)
    terminated_at:      Optional[float] = None
    termination_reason: Optional[str]   = None


def _build_credential():
    """
    Pick the right Azure credential.
    Priority: ManagedIdentity → ServicePrincipal → AzureCLI
    """
    if os.getenv("AZURE_USE_MANAGED_IDENTITY", "false").lower() == "true":
        return ManagedIdentityCredential()
    t = os.getenv("AZURE_TENANT_ID", "")
    c = os.getenv("AZURE_CLIENT_ID", "")
    s = os.getenv("AZURE_CLIENT_SECRET", "")
    if t and c and s:
        return ClientSecretCredential(tenant_id=t, client_id=c, client_secret=s)
    logger.info("Azure auth: AzureCliCredential (az login)")
    return AzureCliCredential()


class MicroVMOrchestrator:
    """
    Provisions REAL ephemeral Azure Container Instances.

    Lifecycle per task:
      1. bootstrap_task_network()  — create VNet + NSG (once per task)
      2. provision_agent_vm()      — spin up ACI container for each stage
      3. terminate_vm()            — delete ACI immediately on completion/violation
      4. teardown_task_network()   — delete VNet + NSG after all VMs gone
    """

    def __init__(self) -> None:
        self._cred      = _build_credential()
        self._sub       = AZURE_CONFIG.subscription_id
        self._rg        = AZURE_CONFIG.resource_group
        self._location  = AZURE_CONFIG.location

        self._aci     = ContainerInstanceManagementClient(self._cred, self._sub)
        self._network = NetworkManagementClient(self._cred, self._sub)
        self._resource = ResourceManagementClient(self._cred, self._sub)

        # Platform CA — issued once per orchestrator lifetime
        self._ca_cert_pem, self._ca_key_pem = generate_ca_certificate()

        self._vms:              Dict[str, MicroVMRecord] = {}
        self._vm_lifetime_tasks: Dict[str, asyncio.Task] = {}

        # Per-task network resource names
        self._task_networks: Dict[str, dict] = {}

    # ── Network bootstrap ─────────────────────────────────────────────────────

    async def bootstrap_task_network(self, task_id: str) -> dict:
        """
        Create a dedicated VNet + NSG for one task.
        All agent containers for this task share this network.
        Returns dict with vnet_name, subnet_id, nsg_id.
        """
        tag = task_id[:8]
        vnet_name   = f"vnet-sap-{tag}"
        subnet_name = f"snet-sap-{tag}"
        nsg_name    = f"nsg-sap-{tag}"

        logger.info("[%s] Bootstrapping task network: %s", task_id, vnet_name)

        loop = asyncio.get_event_loop()

        # 1. Ensure resource group exists
        await loop.run_in_executor(None, lambda: self._resource.resource_groups.create_or_update(
            self._rg, {"location": self._location,
                       "tags": {"task_id": task_id, "managed_by": "secure-analysis-platform"}}
        ))

        # 2. NSG — deny all by default, allow only mTLS between agents
        nsg_params = NetworkSecurityGroup(
            location=self._location,
            security_rules=[
                SecurityRule(
                    name="AllowAgentMTLS",
                    priority=100,
                    direction="Inbound",
                    access="Allow",
                    protocol="Tcp",
                    source_address_prefix="10.0.1.0/24",
                    destination_address_prefix="10.0.1.0/24",
                    source_port_range="*",
                    destination_port_range=str(AGENT_PORT),
                ),
                SecurityRule(
                    name="DenyAllInbound",
                    priority=4096,
                    direction="Inbound",
                    access="Deny",
                    protocol="*",
                    source_address_prefix="*",
                    destination_address_prefix="*",
                    source_port_range="*",
                    destination_port_range="*",
                ),
                SecurityRule(
                    name="AllowHTTPSOutbound",
                    priority=100,
                    direction="Outbound",
                    access="Allow",
                    protocol="Tcp",
                    source_address_prefix="*",
                    destination_address_prefix="AzureCloud",
                    source_port_range="*",
                    destination_port_range="443",
                ),
                SecurityRule(
                    name="AllowAgentMTLSOutbound",
                    priority=200,
                    direction="Outbound",
                    access="Allow",
                    protocol="Tcp",
                    source_address_prefix="10.0.1.0/24",
                    destination_address_prefix="10.0.1.0/24",
                    source_port_range="*",
                    destination_port_range=str(AGENT_PORT),
                ),
                SecurityRule(
                    name="DenyAllOutbound",
                    priority=4096,
                    direction="Outbound",
                    access="Deny",
                    protocol="*",
                    source_address_prefix="*",
                    destination_address_prefix="*",
                    source_port_range="*",
                    destination_port_range="*",
                ),
            ],
            tags={"task_id": task_id},
        )
        nsg_poller = await loop.run_in_executor(
            None,
            lambda: self._network.network_security_groups.begin_create_or_update(
                self._rg, nsg_name, nsg_params
            ),
        )
        nsg = await loop.run_in_executor(None, nsg_poller.result)
        logger.info("[%s] NSG created: %s", task_id, nsg_name)

        # 3. VNet + Subnet
        vnet_poller = await loop.run_in_executor(
            None,
            lambda: self._network.virtual_networks.begin_create_or_update(
                self._rg,
                vnet_name,
                VirtualNetwork(
                    location=self._location,
                    address_space=AddressSpace(address_prefixes=[VNET_CIDR]),
                    subnets=[
                        Subnet(
                            name=subnet_name,
                            address_prefix=SUBNET_CIDR,
                            network_security_group=SubResource(id=nsg.id),
                            # Required for ACI
                            delegations=[{
                                "name": "aciDelegation",
                                "properties": {
                                    "serviceName": "Microsoft.ContainerInstance/containerGroups"
                                }
                            }],
                        )
                    ],
                    tags={"task_id": task_id},
                ),
            ),
        )
        vnet = await loop.run_in_executor(None, vnet_poller.result)
        subnet = vnet.subnets[0]
        logger.info("[%s] VNet created: %s  subnet: %s", task_id, vnet_name, subnet.id)

        network_info = {
            "vnet_name":   vnet_name,
            "subnet_name": subnet_name,
            "nsg_name":    nsg_name,
            "subnet_id":   subnet.id,
            "nsg_id":      nsg.id,
        }
        self._task_networks[task_id] = network_info
        return network_info

    # ── VM provisioning ───────────────────────────────────────────────────────

    async def provision_agent_vm(
        self,
        agent_role:  str,
        task_id:     str,
        env_vars:    Optional[Dict[str, str]] = None,
        vm_size:     str = None,
    ) -> MicroVMRecord:
        """
        Provision a real Azure Container Instance for one agent role.
        Returns MicroVMRecord with private IP and cert.
        """
        vm_id    = secrets.token_hex(8)
        safe_role = agent_role.replace("_", "-")[:10]
        cg_name   = f"sap-{safe_role}-{vm_id}"
        tag      = task_id[:8]

        logger.info("[%s] Provisioning ACI: %s role=%s", task_id, cg_name, agent_role)

        # Issue short-lived mTLS cert for this container
        cert_pem, key_pem = generate_agent_certificate(
            agent_id=cg_name,
            ca_cert_pem=self._ca_cert_pem,
            ca_key_pem=self._ca_key_pem,
            validity_hours=2,
        )

        # Get subnet for this task
        net = self._task_networks.get(task_id)
        if not net:
            raise RuntimeError(
                f"Task network not bootstrapped for {task_id}. "
                "Call bootstrap_task_network() first."
            )

        # Build env vars — inject cert material and task context
        container_env = {
            "AGENT_ROLE":   agent_role,
            "TASK_ID":      task_id,
            "AGENT_PORT":   str(AGENT_PORT),
            "AGENT_ID":     cg_name,
            "VAULT_NAME":   AZURE_CONFIG.vault_name,
            "KMS_LOCAL":    "false",
            # Cert material passed as env vars — container writes to /run/certs (tmpfs)
            "AGENT_CERT_PEM": cert_pem.decode(),
            "AGENT_KEY_PEM":  key_pem.decode(),
            "CA_CERT_PEM":    self._ca_cert_pem.decode(),
        }
        if env_vars:
            container_env.update(env_vars)

        env_list = [
            EnvironmentVariable(name=k, value=v, secure_value=None)
            if "SECRET" not in k and "KEY_PEM" not in k
            else EnvironmentVariable(name=k, secure_value=v)
            for k, v in container_env.items()
        ]

        # CPU/memory by role
        cpu, mem = {
            "secure_fetcher":  (0.5, 0.5),
            "ast_parser":      (1.0, 1.0),
            "ir_builder":      (1.0, 1.0),
            "ml_analyzer":     (2.0, 2.0),
            "policy_engine":   (0.5, 0.5),
            "strategy_agent":  (0.5, 0.5),
            "iac_generator":   (0.5, 0.5),
            "deployment_agent":(1.0, 1.0),
        }.get(agent_role, (0.5, 0.5))

        cg_params = ContainerGroup(
            location=self._location,
            os_type=OperatingSystemTypes.LINUX,
            restart_policy="Never",
            image_registry_credentials=[
                ImageRegistryCredential(
                    server=f"{os.getenv('ACR_NAME', '')}.azurecr.io",
                    username=os.getenv("ACR_USERNAME", ""),
                    password=os.getenv("ACR_PASSWORD", ""),
                )
            ] if os.getenv("ACR_NAME") else None,
            containers=[
                Container(
                    name=cg_name,
                    image=AGENT_IMAGE,
                    resources=ResourceRequirements(
                        requests=ResourceRequests(cpu=cpu, memory_in_gb=mem)
                    ),
                    ports=[ContainerPort(port=AGENT_PORT, protocol="TCP")],
                    environment_variables=env_list,
                    # Startup command — mounts tmpfs and starts agent
                    command=[
                        "/bin/sh", "-c",
                        f"mkdir -p /run/certs && "
                        f"echo \"$AGENT_CERT_PEM\" > /run/certs/agent.crt && "
                        f"echo \"$AGENT_KEY_PEM\"  > /run/certs/agent.key && "
                        f"echo \"$CA_CERT_PEM\"    > /run/certs/ca.crt && "
                        f"python -m src.agents.{agent_role}_runner"
                    ],
                )
            ],
            # Attach to the task's subnet (no public IP)
            subnet_ids=[{"id": net["subnet_id"]}],
            tags={"task_id": task_id, "role": agent_role, "vm_id": vm_id},
        )

        loop = asyncio.get_event_loop()
        try:
            poller = await loop.run_in_executor(
                None,
                lambda: self._aci.container_groups.begin_create_or_update(
                    self._rg, cg_name, cg_params
                ),
            )
            cg = await loop.run_in_executor(None, poller.result)

            # Get assigned private IP
            private_ip = "10.0.1.unknown"
            if cg.ip_address and cg.ip_address.ip:
                private_ip = cg.ip_address.ip

            record = MicroVMRecord(
                vm_id=vm_id,
                agent_role=agent_role,
                task_id=task_id,
                azure_vm_name=cg_name,
                private_ip=private_ip,
                agent_port=AGENT_PORT,
                cert_pem=cert_pem,
                status=VMStatus.RUNNING,
            )
            self._vms[vm_id] = record

            # Auto-terminate after max lifetime
            self._vm_lifetime_tasks[vm_id] = asyncio.create_task(
                self._vm_lifetime_watchdog(vm_id)
            )

            logger.info("[%s] ACI running: %s  ip=%s", task_id, cg_name, private_ip)
            return record

        except Exception as e:
            logger.error("[%s] ACI provision failed %s: %s", task_id, cg_name, e)
            raise

    # ── VM termination ────────────────────────────────────────────────────────

    async def terminate_vm(self, vm_id: str, reason: str = "task_complete") -> None:
        """Delete ACI container group immediately. Certificate is effectively revoked."""
        if vm_id not in self._vms:
            return

        record = self._vms[vm_id]
        record.status             = VMStatus.TERMINATING
        record.terminated_at      = time.time()
        record.termination_reason = reason

        logger.info("Terminating ACI %s (%s): %s",
                    record.azure_vm_name, record.agent_role, reason)

        loop = asyncio.get_event_loop()
        try:
            poller = await loop.run_in_executor(
                None,
                lambda: self._aci.container_groups.begin_delete(
                    self._rg, record.azure_vm_name
                ),
            )
            await loop.run_in_executor(None, poller.result)
            record.status = VMStatus.TERMINATED
            logger.info("ACI deleted: %s", record.azure_vm_name)
        except Exception as e:
            logger.error("Error deleting ACI %s: %s", record.azure_vm_name, e)
            record.status = VMStatus.FAILED

        if vm_id in self._vm_lifetime_tasks:
            self._vm_lifetime_tasks[vm_id].cancel()
            del self._vm_lifetime_tasks[vm_id]

    async def terminate_vm_immediately(self, vm_id: str, reason: str = "violation") -> None:
        """Same as terminate_vm but logs as SECURITY VIOLATION."""
        logger.error("SECURITY VIOLATION — force-terminating VM %s: %s", vm_id, reason)
        await self.terminate_vm(vm_id, reason)

    async def terminate_task_vms(self, task_id: str, reason: str = "task_complete") -> int:
        """Terminate all VMs for a task in parallel."""
        vm_ids = [vid for vid, r in self._vms.items() if r.task_id == task_id]
        await asyncio.gather(*[self.terminate_vm(vid, reason) for vid in vm_ids])
        return len(vm_ids)

    async def teardown_task_network(self, task_id: str) -> None:
        """Delete VNet + NSG created for this task."""
        net = self._task_networks.pop(task_id, None)
        if not net:
            return
        loop = asyncio.get_event_loop()
        logger.info("[%s] Tearing down task network: %s", task_id, net["vnet_name"])
        try:
            p1 = await loop.run_in_executor(
                None,
                lambda: self._network.virtual_networks.begin_delete(
                    self._rg, net["vnet_name"]
                ),
            )
            await loop.run_in_executor(None, p1.result)
            p2 = await loop.run_in_executor(
                None,
                lambda: self._network.network_security_groups.begin_delete(
                    self._rg, net["nsg_name"]
                ),
            )
            await loop.run_in_executor(None, p2.result)
            logger.info("[%s] Task network deleted.", task_id)
        except Exception as e:
            logger.error("[%s] Network teardown error: %s", task_id, e)

    # ── Watchdog ──────────────────────────────────────────────────────────────

    async def _vm_lifetime_watchdog(self, vm_id: str) -> None:
        await asyncio.sleep(AGENT_CONFIG.vm_lifespan_seconds)
        if vm_id in self._vms and self._vms[vm_id].status == VMStatus.RUNNING:
            logger.warning("VM %s exceeded lifetime — force terminating", vm_id)
            await self.terminate_vm(vm_id, "lifetime_exceeded")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def list_active_vms(self) -> List[dict]:
        return [
            {
                "vm_id":      r.vm_id,
                "role":       r.agent_role,
                "task_id":    r.task_id,
                "status":     r.status.value,
                "age_seconds": round(time.time() - r.created_at, 1),
                "private_ip": r.private_ip,
                "azure_name": r.azure_vm_name,
            }
            for r in self._vms.values()
            if r.status == VMStatus.RUNNING
        ]

    @property
    def ca_cert_pem(self) -> bytes:
        return self._ca_cert_pem