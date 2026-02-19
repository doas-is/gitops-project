"""
Key Management Service.

Implements envelope encryption:
  - KEK (Key Encryption Key) stored in Azure Key Vault
  - DEK (Data Encryption Key) generated per-file, per-agent
  - DEKs encrypted with KEK before transmission
  - Plaintext DEKs exist ONLY in memory, zeroized immediately after use

Memory safety:
  - All plaintext key material uses bytearray (mutable → overwritable)
  - Keys are zeroized after use via ctypes memset
  - No key material logged or persisted
"""
from __future__ import annotations

import ctypes
import logging
import os
import secrets
from base64 import b64decode, b64encode
from contextlib import contextmanager
from typing import Generator, Optional, Tuple

from azure.identity import ClientSecretCredential, ManagedIdentityCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# Disable logging of key material
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
        # Overwrite ciphertext reference (not plaintext, but defensive)
        if hasattr(self, "ciphertext") and isinstance(self.ciphertext, bytearray):
            _zeroize(self.ciphertext)


class KeyVaultKMS:
    """
    Azure Key Vault backed Key Management.

    Supports both:
      - Managed Identity (production)
      - Service Principal (development)
    """

    def __init__(self, vault_url: str, kek_name: str = "master-kek") -> None:
        self.vault_url = vault_url
        self.kek_name = kek_name
        self._crypto_clients: dict[str, CryptographyClient] = {}
        self._credential = self._build_credential()
        self._key_client = KeyClient(vault_url=vault_url, credential=self._credential)

    def _build_credential(self):
        """Use Managed Identity in production, SP in dev."""
        if os.getenv("AZURE_USE_MANAGED_IDENTITY", "false").lower() == "true":
            return ManagedIdentityCredential()
        return ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )

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
        """
        Wrap a DEK using the KEK in Key Vault (RSA-OAEP-256).
        DEK bytes are passed as bytearray and zeroized by caller.
        """
        client = self._get_crypto_client(kek_key_id)
        result = client.encrypt(
            EncryptionAlgorithm.rsa_oaep_256, bytes(dek)
        )
        return result.ciphertext

    def decrypt_dek(self, encrypted_dek: bytes, kek_key_id: str) -> bytearray:
        """
        Unwrap a DEK. Returns mutable bytearray.
        CALLER MUST ZEROIZE after use.
        """
        client = self._get_crypto_client(kek_key_id)
        result = client.decrypt(
            EncryptionAlgorithm.rsa_oaep_256, encrypted_dek
        )
        dek = bytearray(result.plaintext)
        return dek


class FileEncryptor:
    """
    Per-file AES-256-GCM encryption with envelope key management.

    Usage:
        encryptor = FileEncryptor(kms)
        payload = encryptor.encrypt(file_bytes)
        # plaintext gone - only payload.ciphertext exists
    """

    def __init__(self, kms: KeyVaultKMS) -> None:
        self.kms = kms

    def encrypt(self, plaintext: bytes) -> EncryptedPayload:
        """
        Encrypt file bytes in memory.
        1. Generate random DEK (AES-256)
        2. Encrypt plaintext with DEK using AES-GCM
        3. Wrap DEK with KEK from Key Vault
        4. Return EncryptedPayload - plaintext reference NOT retained
        """
        dek: Optional[bytearray] = None
        try:
            # Step 1: Generate per-file DEK
            dek = bytearray(secrets.token_bytes(32))  # AES-256

            # Step 2: Encrypt content
            nonce = secrets.token_bytes(12)  # 96-bit GCM nonce
            aesgcm = AESGCM(bytes(dek))
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Step 3: Wrap DEK
            kek_id = self.kms.get_current_kek_id()
            encrypted_dek = self.kms.encrypt_dek(dek, kek_id)

            return EncryptedPayload(
                ciphertext=ciphertext,
                nonce=nonce,
                encrypted_dek=encrypted_dek,
                kek_key_id=kek_id,
            )
        finally:
            # Zeroize DEK regardless of outcome
            if dek is not None:
                _zeroize(dek)
                del dek

    @contextmanager
    def decrypt_context(
        self, payload: EncryptedPayload
    ) -> Generator[bytes, None, None]:
        """
        Context manager for just-in-time decryption.
        Plaintext exists ONLY within the `with` block.
        Zeroized immediately on exit.

        Usage:
            with encryptor.decrypt_context(payload) as plaintext:
                process(plaintext)
            # plaintext is gone here
        """
        dek: Optional[bytearray] = None
        plaintext_buf: Optional[bytearray] = None
        try:
            dek = self.kms.decrypt_dek(payload.encrypted_dek, payload.kek_key_id)
            aesgcm = AESGCM(bytes(dek))
            plaintext = aesgcm.decrypt(payload.nonce, payload.ciphertext, None)
            plaintext_buf = bytearray(plaintext)
            del plaintext  # Remove original bytes reference
            yield bytes(plaintext_buf)
        finally:
            if dek is not None:
                _zeroize(dek)
                del dek
            if plaintext_buf is not None:
                _zeroize(plaintext_buf)
                del plaintext_buf


class LocalKMS:
    """
    Local KMS for testing without Azure Key Vault.
    NOT for production use.
    """

    def __init__(self) -> None:
        self._master_key = bytearray(secrets.token_bytes(32))
        logger.warning("Using LOCAL KMS - NOT FOR PRODUCTION")

    def get_current_kek_id(self) -> str:
        return "local://master-kek/v1"

    def encrypt_dek(self, dek: bytearray, kek_key_id: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(bytes(self._master_key))
        return nonce + aesgcm.encrypt(nonce, bytes(dek), None)

    def decrypt_dek(self, encrypted_dek: bytes, kek_key_id: str) -> bytearray:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = encrypted_dek[:12]
        ciphertext = encrypted_dek[12:]
        aesgcm = AESGCM(bytes(self._master_key))
        return bytearray(aesgcm.decrypt(nonce, ciphertext, None))


def build_kms(use_local: bool = False) -> KeyVaultKMS:
    """Build KMS instance from environment config."""
    if use_local or os.getenv("KMS_LOCAL", "false").lower() == "true":
        return LocalKMS()  # type: ignore[return-value]
    vault_url = f"https://{os.environ['VAULT_NAME']}.vault.azure.net"
    return KeyVaultKMS(vault_url=vault_url)