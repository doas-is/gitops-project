"""
Key Management Service.

Implements envelope encryption:
  - KEK (Key Encryption Key) stored in Azure Key Vault
  - DEK (Data Encryption Key) generated per-file, per-agent
  - DEKs encrypted with KEK before transmission
  - Plaintext DEKs exist ONLY in memory, zeroized immediately after use

Auth modes (in priority order):
  1. Managed Identity  — set AZURE_USE_MANAGED_IDENTITY=true
  2. Service Principal — set AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET
  3. Azure CLI login   — fallback when no SP env vars set (az login already done)
"""
from __future__ import annotations

import ctypes
import logging
import os
import secrets
from base64 import b64encode
from contextlib import contextmanager
from typing import Generator, Optional

from azure.identity import (
    AzureCliCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
    ManagedIdentityCredential,
)
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)
logging.getLogger("azure").setLevel(logging.WARNING)


def _zeroize(buf: bytearray) -> None:
    """Securely overwrite memory buffer with zeros."""
    if len(buf) > 0:
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


class EncryptedPayload:
    """Container for encrypted data. Never stores plaintext."""
    __slots__ = ("ciphertext", "nonce", "encrypted_dek", "kek_key_id")

    def __init__(
        self,
        ciphertext: bytes,
        nonce: bytes,
        encrypted_dek: bytes,
        kek_key_id: str,
    ) -> None:
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.encrypted_dek = encrypted_dek
        self.kek_key_id = kek_key_id

    def ciphertext_b64(self) -> str:
        return b64encode(self.ciphertext).decode()

    def nonce_b64(self) -> str:
        return b64encode(self.nonce).decode()

    def encrypted_dek_b64(self) -> str:
        return b64encode(self.encrypted_dek).decode()

    def __del__(self):
        if hasattr(self, "ciphertext") and isinstance(self.ciphertext, bytearray):
            _zeroize(self.ciphertext)


class KeyVaultKMS:
    """
    Azure Key Vault backed Key Management.

    Credential selection now respects az login correctly:
      1. AZURE_USE_MANAGED_IDENTITY=true  → ManagedIdentityCredential
      2. All three SP vars present         → ClientSecretCredential
      3. Otherwise                         → AzureCliCredential  (az login)
    The old code always called ClientSecretCredential and crashed when
    AZURE_TENANT_ID/CLIENT_ID were empty (i.e. az-login-only deployments).
    """

    def __init__(self, vault_url: str, kek_name: str = "master-kek") -> None:
        self.vault_url = vault_url
        self.kek_name = kek_name
        self._crypto_clients: dict[str, CryptographyClient] = {}
        self._credential = self._build_credential()
        self._key_client = KeyClient(vault_url=vault_url, credential=self._credential)

    @staticmethod
    def _build_credential():
        """
        Pick the right Azure credential.

        Priority:
          1. Managed Identity  (AZURE_USE_MANAGED_IDENTITY=true)
          2. Service Principal (all three SP vars set)
          3. Azure CLI login   (fallback — works after `az login`)
        """
        if os.getenv("AZURE_USE_MANAGED_IDENTITY", "false").lower() == "true":
            logger.info("KMS auth: ManagedIdentityCredential")
            return ManagedIdentityCredential()

        tenant = os.getenv("AZURE_TENANT_ID", "")
        client = os.getenv("AZURE_CLIENT_ID", "")
        secret = os.getenv("AZURE_CLIENT_SECRET", "")

        if tenant and client and secret:
            logger.info("KMS auth: ClientSecretCredential (service principal)")
            return ClientSecretCredential(
                tenant_id=tenant,
                client_id=client,
                client_secret=secret,
            )

        # Fallback: use whatever `az login` cached — works for developers
        logger.info("KMS auth: AzureCliCredential (az login)")
        return AzureCliCredential()

    def _get_crypto_client(self, key_id: str) -> CryptographyClient:
        if key_id not in self._crypto_clients:
            self._crypto_clients[key_id] = CryptographyClient(
                key_id, credential=self._credential
            )
        return self._crypto_clients[key_id]

    def get_current_kek_id(self) -> str:
        """Return the current Key Vault key ID for the KEK."""
        key = self._key_client.get_key(self.kek_name)
        return key.id

    def encrypt_dek(self, dek: bytearray, kek_key_id: str) -> bytes:
        """Wrap a DEK using RSA-OAEP-256."""
        client = self._get_crypto_client(kek_key_id)
        result = client.encrypt(EncryptionAlgorithm.rsa_oaep_256, bytes(dek))
        return result.ciphertext

    def decrypt_dek(self, encrypted_dek: bytes, kek_key_id: str) -> bytearray:
        """Unwrap a DEK. Caller MUST zeroize the returned bytearray."""
        client = self._get_crypto_client(kek_key_id)
        result = client.decrypt(EncryptionAlgorithm.rsa_oaep_256, encrypted_dek)
        return bytearray(result.plaintext)


class LocalKMS:
    """
    Local KMS for testing without Azure Key Vault.
    Activated by KMS_LOCAL=true in .env.
    NOT for production use.
    """

    def __init__(self) -> None:
        self._master_key = bytearray(secrets.token_bytes(32))
        logger.warning("Using LOCAL KMS — NOT FOR PRODUCTION")

    def get_current_kek_id(self) -> str:
        return "local://master-kek/v1"

    def encrypt_dek(self, dek: bytearray, kek_key_id: str) -> bytes:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(bytes(self._master_key))
        return nonce + aesgcm.encrypt(nonce, bytes(dek), None)

    def decrypt_dek(self, encrypted_dek: bytes, kek_key_id: str) -> bytearray:
        nonce = encrypted_dek[:12]
        ciphertext = encrypted_dek[12:]
        aesgcm = AESGCM(bytes(self._master_key))
        return bytearray(aesgcm.decrypt(nonce, ciphertext, None))


class FileEncryptor:
    """
    Per-file AES-256-GCM encryption with envelope key management.
    Plaintext exists only inside decrypt_context(); zeroized on exit.
    """

    def __init__(self, kms) -> None:
        self.kms = kms

    def encrypt(self, plaintext: bytes) -> EncryptedPayload:
        """
        1. Generate random DEK (AES-256)
        2. Encrypt plaintext with DEK (AES-GCM)
        3. Wrap DEK with KEK from Key Vault
        4. Return EncryptedPayload — plaintext NOT retained
        """
        dek: Optional[bytearray] = None
        try:
            dek = bytearray(secrets.token_bytes(32))
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(bytes(dek))
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            kek_id = self.kms.get_current_kek_id()
            encrypted_dek = self.kms.encrypt_dek(dek, kek_id)
            return EncryptedPayload(
                ciphertext=ciphertext,
                nonce=nonce,
                encrypted_dek=encrypted_dek,
                kek_key_id=kek_id,
            )
        finally:
            if dek is not None:
                _zeroize(dek)
                del dek

    @contextmanager
    def decrypt_context(
        self, payload: EncryptedPayload
    ) -> Generator[bytes, None, None]:
        """
        JIT decryption context manager.
        Plaintext exists ONLY within the `with` block, then zeroized.
        """
        dek: Optional[bytearray] = None
        plaintext_buf: Optional[bytearray] = None
        try:
            dek = self.kms.decrypt_dek(payload.encrypted_dek, payload.kek_key_id)
            aesgcm = AESGCM(bytes(dek))
            plaintext = aesgcm.decrypt(payload.nonce, payload.ciphertext, None)
            plaintext_buf = bytearray(plaintext)
            del plaintext
            yield bytes(plaintext_buf)
        finally:
            if dek is not None:
                _zeroize(dek)
                del dek
            if plaintext_buf is not None:
                _zeroize(plaintext_buf)
                del plaintext_buf


def build_kms(use_local: bool = False):
    """
    Build KMS instance from environment.
    KMS_LOCAL=true → LocalKMS (no Azure needed)
    Otherwise      → KeyVaultKMS with auto-credential selection
    """
    if use_local or os.getenv("KMS_LOCAL", "false").lower() == "true":
        return LocalKMS()

    vault_name = os.getenv("VAULT_NAME", "")
    if not vault_name:
        raise EnvironmentError(
            "VAULT_NAME must be set in .env when KMS_LOCAL=false. "
            "Example: VAULT_NAME=my-key-vault"
        )
    vault_url = f"https://{vault_name}.vault.azure.net"
    return KeyVaultKMS(vault_url=vault_url)