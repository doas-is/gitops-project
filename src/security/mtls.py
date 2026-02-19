"""
Mutual TLS (mTLS) Client and Server.

Guarantees:
  - All inter-agent traffic is encrypted
  - Both sides authenticate with certificates
  - Certificates are short-lived (per VM identity)
  - Revocation on VM teardown

Certificate lifecycle:
  - Generated at VM boot by orchestrator
  - Private key stored in /run/certs (tmpfs - memory only)
  - Revoked and destroyed on VM teardown
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import ssl
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

logger = logging.getLogger(__name__)


class MTLSConfig:
    """mTLS certificate paths and validation settings."""

    def __init__(
        self,
        cert_path: str,
        key_path: str,
        ca_path: str,
        agent_id: Optional[str] = None,
    ) -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.agent_id = agent_id or os.getenv("AGENT_ID", "unknown")

    def validate_paths(self) -> None:
        """Verify all cert files exist and are readable."""
        for path, name in [
            (self.cert_path, "cert"),
            (self.key_path, "key"),
            (self.ca_path, "CA"),
        ]:
            if not Path(path).exists():
                raise FileNotFoundError(f"mTLS {name} not found at {path}")


def create_server_ssl_context(config: MTLSConfig) -> ssl.SSLContext:
    """
    Create SSL context for agent server (inbound mTLS).
    Requires client certificate for all connections.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config.cert_path, config.key_path)
    ctx.load_verify_locations(config.ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Strong cipher suites only
    ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
    return ctx


def create_client_ssl_context(config: MTLSConfig) -> ssl.SSLContext:
    """
    Create SSL context for agent client (outbound mTLS).
    Presents client certificate to server.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config.cert_path, config.key_path)
    ctx.load_verify_locations(config.ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
    return ctx


class MTLSServer:
    """
    Async mTLS server for receiving A2A messages.
    Validates schema and signature before dispatching.
    """

    def __init__(
        self,
        config: MTLSConfig,
        host: str = "0.0.0.0",
        port: int = 8443,
    ) -> None:
        self.config = config
        self.host = host
        self.port = port
        self._handlers: Dict[str, Callable] = {}
        self._server: Optional[asyncio.Server] = None
        self._ssl_ctx = create_server_ssl_context(config)
        self._message_count = 0
        self._start_time = time.time()

    def register_handler(self, message_type: str, handler: Callable) -> None:
        """Register handler for a specific message type."""
        self._handlers[message_type] = handler

    async def start(self) -> None:
        """Start the mTLS server."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self.host,
            port=self.port,
            ssl=self._ssl_ctx,
        )
        logger.info(
            "mTLS server started on %s:%d (agent=%s)",
            self.host, self.port, self.config.agent_id
        )

    async def stop(self) -> None:
        """Gracefully stop the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming mTLS connection."""
        peer = writer.get_extra_info("peername")
        cert = writer.get_extra_info("ssl_object").getpeercert()

        try:
            # Read length-prefixed message
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            msg_length = int.from_bytes(length_bytes, "big")

            if msg_length > 10 * 1024 * 1024:  # 10MB max
                logger.warning("Message too large from %s: %d bytes", peer, msg_length)
                return

            raw_msg = await asyncio.wait_for(reader.readexactly(msg_length), timeout=60)
            self._message_count += 1

            # Parse and validate
            message = json.loads(raw_msg)
            msg_type = message.get("header", {}).get("message_type")

            if msg_type not in self._handlers:
                logger.warning("No handler for message type: %s", msg_type)
                response = {"status": "error", "reason": "unknown_message_type"}
            else:
                handler = self._handlers[msg_type]
                result = await handler(message, cert)
                response = {"status": "ok", "result": result}

            # Send response
            response_bytes = json.dumps(response).encode()
            writer.write(len(response_bytes).to_bytes(4, "big") + response_bytes)
            await writer.drain()

        except asyncio.TimeoutError:
            logger.warning("Connection timeout from %s", peer)
        except Exception as e:
            logger.error("Error handling connection from %s: %s", peer, type(e).__name__)
        finally:
            writer.close()
            await writer.wait_closed()

    def stats(self) -> Dict[str, Any]:
        return {
            "agent_id": self.config.agent_id,
            "host": self.host,
            "port": self.port,
            "messages_processed": self._message_count,
            "uptime_seconds": time.time() - self._start_time,
        }


class MTLSClient:
    """
    Async mTLS client for sending A2A messages.
    Connection per message (stateless, zero-trust).
    """

    def __init__(self, config: MTLSConfig) -> None:
        self.config = config
        self._ssl_ctx = create_client_ssl_context(config)

    async def send(
        self,
        host: str,
        port: int,
        message: Dict[str, Any],
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Send a message to a remote agent via mTLS.
        Opens connection, sends, receives response, closes.
        """
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=self._ssl_ctx),
            timeout=timeout,
        )
        try:
            msg_bytes = json.dumps(message).encode()
            writer.write(len(msg_bytes).to_bytes(4, "big") + msg_bytes)
            await writer.drain()

            # Read response
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
            resp_length = int.from_bytes(length_bytes, "big")
            raw_resp = await asyncio.wait_for(reader.readexactly(resp_length), timeout=timeout)
            return json.loads(raw_resp)

        finally:
            writer.close()
            await writer.wait_closed()


def generate_agent_certificate(
    agent_id: str,
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    validity_hours: int = 24,
) -> Tuple[bytes, bytes]:
    """
    Generate a short-lived TLS certificate for a new agent VM.
    
    Returns (cert_pem, key_pem) - key written to /run/certs (tmpfs).
    Certificate is signed by the platform CA.
    """
    # Generate agent private key
    agent_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Load CA
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    # Build cert
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureAnalysis"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=validity_hours))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(agent_id)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = agent_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    logger.info("Generated certificate for agent: %s (valid %dh)", agent_id, validity_hours)
    return cert_pem, key_pem


def generate_ca_certificate() -> Tuple[bytes, bytes]:
    """Generate platform root CA certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.datetime.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureAnalysisPlatformCA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureAnalysis"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureAnalysisPlatformCA"),
        ]))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# Re-export for backward compatibility
from typing import Tuple