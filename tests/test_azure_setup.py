"""Unit tests for Azure setup module."""

import unittest
from unittest.mock import Mock, patch, MagicMock

from config.azure_config import AzureConfig


class TestAzureConfig(unittest.TestCase):
    """Test Azure configuration."""
    
    def test_azure_config_attributes(self):
        """Test that all required config attributes exist."""
        required_attrs = [
            'SUBSCRIPTION_ID', 'TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET',
            'RESOURCE_GROUP_NAME', 'LOCATION', 'VAULT_NAME', 'VM_NAME'
        ]
        
        for attr in required_attrs:
            self.assertTrue(hasattr(AzureConfig, attr))
    
    def test_nsg_rules_configuration(self):
        """Test NSG rules are properly configured."""
        self.assertIn('AllowSSH', AzureConfig.NSG_RULES)
        self.assertIn('AllowHTTPS', AzureConfig.NSG_RULES)
        self.assertIn('DenyAllInbound', AzureConfig.NSG_RULES)
        
        ssh_rule = AzureConfig.NSG_RULES['AllowSSH']
        self.assertEqual(ssh_rule['destination_port_range'], '22')
        self.assertEqual(ssh_rule['protocol'], 'Tcp')
    
    def test_key_configuration(self):
        """Test key configuration."""
        self.assertEqual(AzureConfig.KEY_SIZE, 2048)
        self.assertTrue(AzureConfig.RSA_PUBLIC_KEY_NAME)
        self.assertTrue(AzureConfig.RSA_PRIVATE_KEY_NAME)


class TestKeyManagement(unittest.TestCase):
    """Test cryptographic key management."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_size = 2048
    
    def test_rsa_key_generation(self):
        """Test RSA key pair generation."""
        from src.key_management import KeyManagement
        
        km = KeyManagement()
        km.generate_rsa_keys()
        
        self.assertIsNotNone(km.private_key)
        self.assertIsNotNone(km.public_key)
    
    def test_key_serialization(self):
        """Test key serialization to PEM format."""
        from src.key_management import KeyManagement
        
        km = KeyManagement()
        km.generate_rsa_keys()
        
        private_pem = km.get_private_key_pem()
        public_pem = km.get_public_key_pem()
        
        self.assertTrue(private_pem.startswith(b'-----BEGIN PRIVATE KEY-----'))
        self.assertTrue(public_pem.startswith(b'-----BEGIN PUBLIC KEY-----'))


if __name__ == '__main__':
    unittest.main()