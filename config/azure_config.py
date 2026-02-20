"""
Azure platform configuration.
All values sourced from environment — never hardcoded.

Authentication note:
  This platform supports two Azure auth modes:
    1. Azure CLI login (az login) — recommended for local dev.
       Only RESOURCE_GROUP_NAME and VAULT_NAME are required.
    2. Service-principal env vars — for CI/CD or production.
       Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID,
       AZURE_CLIENT_SECRET, RESOURCE_GROUP_NAME, VAULT_NAME.

All fields default to "" so the module always imports cleanly.
Actual Azure calls will fail with a clear EnvironmentError if
required credentials are missing — not at import time.
"""
import os
from dataclasses import dataclass, field

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass(frozen=True)
class AzureConfig:
    # ── Service-principal creds (optional when using az login, which i am) ──────────────
    subscription_id: str = field(default_factory=lambda: os.getenv("AZURE_SUBSCRIPTION_ID", ""))
    tenant_id:       str = field(default_factory=lambda: os.getenv("AZURE_TENANT_ID", ""))
    client_id:       str = field(default_factory=lambda: os.getenv("AZURE_CLIENT_ID", ""))
    client_secret:   str = field(default_factory=lambda: os.getenv("AZURE_CLIENT_SECRET", ""))

    # ── Required for any deployment ──────────────────────────────────────────
    resource_group: str = field(default_factory=lambda: os.getenv("RESOURCE_GROUP_NAME", "rg-secure-analysis"))
    location:       str = field(default_factory=lambda: os.getenv("LOCATION", "eastus"))
    vault_name:     str = field(default_factory=lambda: os.getenv("VAULT_NAME", ""))

    # ── VM / container defaults ──────────────────────────────────────────────
    vm_size:           str = field(default_factory=lambda: os.getenv("VM_SIZE",           "Standard_B2s"))
    vm_image:          str = field(default_factory=lambda: os.getenv("VM_IMAGE",          "UbuntuLTS"))
    vm_admin_username: str = field(default_factory=lambda: os.getenv("VM_ADMIN_USERNAME", "azureuser"))

    # ── mTLS paths ───────────────────────────────────────────────────────────
    mtls_cert_path: str = field(default_factory=lambda: os.getenv("MTLS_CERT_PATH", "/tmp/agent.crt"))
    mtls_key_path:  str = field(default_factory=lambda: os.getenv("MTLS_KEY_PATH",  "/tmp/agent.key"))
    mtls_ca_path:   str = field(default_factory=lambda: os.getenv("MTLS_CA_PATH",   "/tmp/ca.crt"))

    # ── Misc ─────────────────────────────────────────────────────────────────
    github_repo_url: str = field(default_factory=lambda: os.getenv("GITHUB_REPO_URL", ""))

    def require_azure_creds(self) -> None:
        """
        Call this before any real Azure API call.
        In CLI-login mode only VAULT_NAME is strictly required.
        In service-principal mode all four SP fields must be set.
        """
        missing: list[str] = []
        if not self.vault_name:
            missing.append("VAULT_NAME")
        # If any SP field is set, all must be set (partial SP config is invalid)
        sp_fields = {
            "AZURE_TENANT_ID":     self.tenant_id,
            "AZURE_CLIENT_ID":     self.client_id,
            "AZURE_CLIENT_SECRET": self.client_secret,
        }
        sp_set = sum(1 for v in sp_fields.values() if v)
        if 0 < sp_set < len(sp_fields):
            missing.extend(k for k, v in sp_fields.items() if not v)
        if missing:
            raise EnvironmentError(
                f"Missing Azure configuration: {missing}. "
                "Either use 'az login' (CLI mode) and set VAULT_NAME, "
                "or set all service-principal variables in your .env file."
            )

    @property
    def using_sp_auth(self) -> bool:
        """True when all service-principal fields are present."""
        return bool(self.tenant_id and self.client_id and self.client_secret)


@dataclass(frozen=True)
class AgentConfig:
    """Per-agent runtime configuration. No external dependencies."""
    # VM lifecycle
    vm_lifespan_seconds:  int  = 3600
    destroy_on_violation: bool = True
    destroy_on_completion:bool = True

    # Memory limits (bytes)
    max_file_size:    int = 10  * 1024 * 1024   # 10 MB
    max_total_memory: int = 512 * 1024 * 1024   # 512 MB

    # Policy thresholds
    ml_risk_threshold:           float = 0.75
    policy_confidence_threshold: float = 0.85
    hitl_escalation_threshold:   float = 0.60

    # Crypto
    dek_size_bytes:     int = 32
    kek_algorithm:      str = "RSA-OAEP-256"
    symmetric_algorithm:str = "AES-256-GCM"

AZURE_CONFIG = AzureConfig()
AGENT_CONFIG  = AgentConfig()