#!/usr/bin/env python3
"""
setup_fixes.py  —  Run this ONCE from your project root.

What it does:
  1. Detects whether you have a real Azure Key Vault or not
  2. Updates your .env with the correct settings
  3. Verifies all previously-fixed source files are in place
  4. Tells you exactly what was changed and what to do next

Usage:
    python setup_fixes.py
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

# ── Detect project root ───────────────────────────────────────────────────────
ROOT = Path(__file__).parent
ENV_FILE = ROOT / ".env"

print("=" * 60)
print("Secure Analysis Platform — Setup & Fix")
print("=" * 60)

# ── Load current .env ─────────────────────────────────────────────────────────
env_lines = []
env_dict  = {}
if ENV_FILE.exists():
    for line in ENV_FILE.read_text().splitlines():
        env_lines.append(line)
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            env_dict[k.strip()] = v.strip()

def set_env(key: str, value: str, comment: str = ""):
    """Update or add a key in .env"""
    global env_lines
    for i, line in enumerate(env_lines):
        if line.strip().startswith(f"{key}=") or line.strip() == f"{key}=":
            env_lines[i] = f"{key}={value}"
            return
    if comment:
        env_lines.append(f"\n# {comment}")
    env_lines.append(f"{key}={value}")

# ── Step 1: Check Azure Key Vault ─────────────────────────────────────────────
print("\n[1/4] Checking Azure Key Vault...")

vault_name = env_dict.get("VAULT_NAME", "").strip()
kms_local  = env_dict.get("KMS_LOCAL", "false").lower()

# kms_vault is the placeholder — it's not a real vault
if vault_name in ("", "kms_vault", "your-key-vault-name"):
    print("  ⚠  VAULT_NAME is not configured (placeholder value detected)")
    vault_name = ""

real_vault_found = False
if vault_name:
    # Validate: Azure vault names can't have underscores, must be 3-24 chars
    if "_" in vault_name:
        print(f"  ❌  VAULT_NAME='{vault_name}' contains underscore — invalid Azure DNS name")
        vault_name = ""
    elif len(vault_name) < 3 or len(vault_name) > 24:
        print(f"  ❌  VAULT_NAME='{vault_name}' must be 3–24 characters")
        vault_name = ""
    else:
        # Try to reach it
        try:
            result = subprocess.run(
                ["az", "keyvault", "show", "--name", vault_name, "--query", "name", "-o", "tsv"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                print(f"  ✓  Key Vault found: {vault_name}")
                real_vault_found = True
            else:
                print(f"  ❌  Key Vault '{vault_name}' not found in Azure")
                vault_name = ""
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("  ⚠  Could not reach Azure CLI — assuming vault not available")
            vault_name = ""

if not real_vault_found:
    print("  → Using LOCAL KMS (no Azure Key Vault needed)")
    print("    To use a real vault later:")
    print("      az keyvault create --name kv-secanalysis --resource-group rg-secure-analysis --location eastus")
    print("      az keyvault key create --vault-name kv-secanalysis --name master-kek --kty RSA --size 2048")
    set_env("KMS_LOCAL", "true", "KMS: use local (no Azure Key Vault)")
    if vault_name:
        set_env("VAULT_NAME", vault_name)
    else:
        set_env("VAULT_NAME", "")
else:
    set_env("KMS_LOCAL", "false")
    set_env("VAULT_NAME", vault_name)
    # Check if master-kek exists
    try:
        r = subprocess.run(
            ["az", "keyvault", "key", "show", "--vault-name", vault_name, "--name", "master-kek"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            print(f"\n  ⚠  Key 'master-kek' not found in vault — creating it...")
            subprocess.run(
                ["az", "keyvault", "key", "create", "--vault-name", vault_name,
                 "--name", "master-kek", "--kty", "RSA", "--size", "2048"],
                check=True, timeout=30
            )
            print("  ✓  master-kek created")
    except Exception as e:
        print(f"  ⚠  Could not verify master-kek: {e}")

# ── Step 2: Fix .env paths for Windows ───────────────────────────────────────
print("\n[2/4] Checking .env configuration...")

import tempfile
tmp = tempfile.gettempdir()

set_env("MTLS_CERT_PATH", f"{tmp}/agent.crt".replace("\\", "/"))
set_env("MTLS_KEY_PATH",  f"{tmp}/agent.key".replace("\\", "/"))
set_env("MTLS_CA_PATH",   f"{tmp}/ca.crt".replace("\\", "/"))

# DRY_RUN should be true unless explicitly set to false
if env_dict.get("AZURE_DEPLOY_DRY_RUN", "").lower() not in ("false",):
    set_env("AZURE_DEPLOY_DRY_RUN", "true", "Set to false when ready for real Azure deployments")

ENV_FILE.write_text("\n".join(env_lines) + "\n")
print("  ✓  .env updated")

# ── Step 3: Verify source files ───────────────────────────────────────────────
print("\n[3/4] Checking source files...")

FIXES_DIR = Path(__file__).parent  # fixes are dropped next to this script

FILE_MAP = {
    "a2a_schemas.py":    ROOT / "src" / "schemas" / "a2a_schemas.py",
    "key_management.py": ROOT / "src" / "key_management.py",
    "main.py":           ROOT / "src" / "main.py",
    "repo_cloner.py":    ROOT / "src" / "repo_cloner.py",
    "monitor.py":        ROOT / "ui" / "monitor.py",
    "zero_trust.py":     ROOT / "src" / "security" / "zero_trust.py",
}

# Signature strings that must exist in the fixed versions
SIGNATURES = {
    "a2a_schemas.py":    "cognitive_complexity: int = 0",
    "key_management.py": "AzureCliCredential",
    "main.py":           'os.getenv("KMS_LOCAL", "false").lower() == "true"',
    "repo_cloner.py":    "_validate_token",
}

for fname, dest in FILE_MAP.items():
    src_path = FIXES_DIR / fname
    if not src_path.exists():
        print(f"  ⚠  {fname} — fix file not found next to this script, skipping")
        continue

    # Check if destination already has the fix
    needs_copy = True
    if dest.exists() and fname in SIGNATURES:
        content = dest.read_text(errors="replace")
        if SIGNATURES[fname] in content:
            print(f"  ✓  {dest.relative_to(ROOT)} — already up to date")
            needs_copy = False

    if needs_copy:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dest)
        print(f"  ✓  {dest.relative_to(ROOT)} — updated")

# ── Step 4: Fix parser.py __future__ issue ────────────────────────────────────
print("\n[4/4] Checking parser.py...")

parser_path = ROOT / "src" / "parser.py"
if parser_path.exists():
    content = parser_path.read_text(errors="replace")
    lines = content.splitlines()
    # The stray one-liner docstring must be removed if it appears before the real docstring
    if lines and lines[0].startswith('"""') and lines[0].endswith('"""') and len(lines[0]) > 10:
        # Single-line docstring on line 1 — remove it
        fixed = "\n".join(lines[1:])
        parser_path.write_text(fixed)
        print("  ✓  parser.py — removed stray one-liner docstring (fixes __future__ error)")
    else:
        print("  ✓  parser.py — looks fine")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("✅  Setup complete!")
print()
if not real_vault_found:
    print("  Running in LOCAL KMS mode (KMS_LOCAL=true)")
    print("  Azure Key Vault is NOT required to run the pipeline")
    print()
print("  Start the platform:")
print("    python run.py")
print()
print("  The pipeline will:")
print("    • Fetch files from GitHub (real)")
print("    • Encrypt with local AES-256-GCM key (real)")  
print("    • Parse, build IR, ML score (real)")
print("    • Generate Terraform + Ansible IaC (real)")
print("    • Simulate Azure VM provisioning (visualized in UI)")
print("    • Deploy dry-run (AZURE_DEPLOY_DRY_RUN=true)")
print()
print("  To enable real Azure deployments:")
print("    1. Create Key Vault:  az keyvault create --name kv-secanalysis \\")
print("                            --resource-group rg-secure-analysis --location eastus")
print("    2. Create KEK key:    az keyvault key create --vault-name kv-secanalysis \\")
print("                            --name master-kek --kty RSA --size 2048")
print("    3. Update .env:       VAULT_NAME=kv-secanalysis  KMS_LOCAL=false")
print("    4. Run setup again:   python setup_fixes.py")
print("=" * 60)