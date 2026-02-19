"""Azure configuration and constants."""

import os
from dotenv import load_dotenv

load_dotenv()

class AzureConfig:
    """Azure configuration settings."""
    
    # Authentication
    SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')
    TENANT_ID = os.getenv('AZURE_TENANT_ID')
    CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
    CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
    
    # Resources
    RESOURCE_GROUP_NAME = os.getenv('RESOURCE_GROUP_NAME', 'secure-clone-rg')
    LOCATION = os.getenv('LOCATION', 'eastus')
    VAULT_NAME = os.getenv('VAULT_NAME', 'secure-vault')
    
    # VM Configuration
    VM_NAME = os.getenv('VM_NAME', 'secure-vm-01')
    VM_SIZE = os.getenv('VM_SIZE', 'Standard_B2s')
    VM_IMAGE = os.getenv('VM_IMAGE', 'UbuntuLTS')
    VM_ADMIN_USERNAME = os.getenv('VM_ADMIN_USERNAME', 'azureuser')
    
    # Repository
    GITHUB_REPO_URL = os.getenv('GITHUB_REPO_URL')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Key Configuration
    KEY_SIZE = 2048
    RSA_PUBLIC_KEY_NAME = 'github-clone-public-key'
    RSA_PRIVATE_KEY_NAME = 'github-clone-private-key'
    
    # NSG Configuration
    NSG_NAME = 'secure-clone-nsg'
    NSG_RULES = {
        'AllowSSH': {
            'priority': 100,
            'direction': 'Inbound',
            'protocol': 'Tcp',
            'source_port_range': '*',
            'destination_port_range': '22',
            'source_address_prefix': '*',
            'destination_address_prefix': '*',
            'access': 'Allow'
        },
        'AllowHTTPS': {
            'priority': 110,
            'direction': 'Inbound',
            'protocol': 'Tcp',
            'source_port_range': '*',
            'destination_port_range': '443',
            'source_address_prefix': '*',
            'destination_address_prefix': '*',
            'access': 'Allow'
        },
        'DenyAllInbound': {
            'priority': 4096,
            'direction': 'Inbound',
            'protocol': '*',
            'source_port_range': '*',
            'destination_port_range': '*',
            'source_address_prefix': '*',
            'destination_address_prefix': '*',
            'access': 'Deny'
        }
    }

    @classmethod
    def validate(cls):
        """Validate required configuration."""
        required = [
            'SUBSCRIPTION_ID', 'TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET'
        ]
        missing = [attr for attr in required if not getattr(cls, attr)]
        if missing:
            raise ValueError(f"Missing required Azure configuration: {', '.join(missing)}")