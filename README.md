# Secure GitHub Clone with Azure Integration

A Python project that securely clones GitHub repositories with automatic Azure VM provisioning, cryptographic key management, and Network Security Group (NSG) configuration.

## Architecture Overview

### Phase 1: VM1 - Secure Project Compilation
- Creates an Azure VM with integrated key management
- Generates RSA key pair (public key in Azure Key Vault, private key stored in VM)
- Implements transit encryption for secure cloning
- Establishes NSG rules for network isolation
- Single VM handles project compilation and implementation

### Phase 2: VM2 - Security Validation (Future)
- Separate VM for file-by-file compilation
- Validates compiled code for injection attacks
- Ensures no security risks in codebase

## Prerequisites

- Python 3.8+
- Azure Account with active subscription
- Azure CLI installed and configured
- Git installed

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-github-clone.git
cd secure-github-clone

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env with your Azure credentials