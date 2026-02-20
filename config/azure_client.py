from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from config.azure_config import AZURE_CONFIG

credential = DefaultAzureCredential()

resource_client = ResourceManagementClient(
    credential,
    AZURE_CONFIG.subscription_id
)