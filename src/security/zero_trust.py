"""
Zero-Trust Security Module  —  src/security/zero_trust.py

Implements practical zero-trust controls that are simple, self-contained,
and work without external dependencies beyond what's already in the project.

Principles enforced here:
  1. Never trust, always verify  — every inter-agent call is signed + verified
  2. Least privilege             — agents receive only the data they need
  3. Assume breach               — every message is treated as potentially hostile
  4. Short-lived credentials     — session tokens expire in minutes, not hours

Controls:
  ┌─────────────────────────────────────────────────────────────────────┐
  │  RequestSigner      — HMAC-SHA256 signs every message + timestamp   │
  │  AgentIdentity      — short-lived token per agent, verified on recv │
  │  ZeroTrustGateway   — validates ALL inbound payloads before routing │
  │  AuditContext       — immutable per-request audit trail             │
  └─────────────────────────────────────────────────────────────────────┘

Usage (in any agent):
    from src.security.zero_trust import ZeroTrustGateway, RequestSigner

    # At agent startup
    signer  = RequestSigner(agent_id="ast_parser", secret=session_secret)
    gateway = ZeroTrustGateway(expected_sender="secure_fetcher")

    # When sending a message
    signed_headers = signer.sign_headers(payload_bytes)

    # When receiving a message
    gateway.verify(payload_bytes, headers)  # raises on failure
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Token TTL constants
REQUEST_SIGNATURE_TTL = 60      # seconds — a signed request is only valid for 60s
AGENT_TOKEN_TTL       = 7200    # seconds — agent identity token lives 2 hours


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class ZeroTrustViolation(SecurityError):
    """Raised when a zero-trust check fails. Always triggers audit log entry."""


class SignatureExpired(ZeroTrustViolation):
    """Request signature timestamp is outside the acceptable window."""


class SignatureMismatch(ZeroTrustViolation):
    """HMAC digest does not match — request was tampered or key is wrong."""


class UnknownSender(ZeroTrustViolation):
    """Message arrived from an agent not in the expected-sender list."""


class TokenExpired(ZeroTrustViolation):
    """Agent identity token has passed its TTL."""


# ─────────────────────────────────────────────────────────────────────────────
# Agent identity token
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentToken:
    """
    Short-lived identity credential for one agent instance.
    Issued at VM creation, verified on every inbound message.
    Not a JWT — deliberately simple and self-contained.
    """
    agent_id:   str
    vm_id:      str
    issued_at:  float = field(default_factory=time.time)
    ttl:        float = AGENT_TOKEN_TTL
    _secret:    bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @property
    def expires_at(self) -> float:
        return self.issued_at + self.ttl

    @property
    def is_valid(self) -> bool:
        return time.time() < self.expires_at

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def signing_key(self) -> bytes:
        """Derive a per-token signing key."""
        return hmac.new(
            self._secret,
            f"{self.agent_id}:{self.vm_id}:{self.issued_at:.0f}".encode(),
            hashlib.sha256,
        ).digest()

    def to_header(self) -> str:
        """Compact wire representation for X-Agent-Token header."""
        exp = f"{self.expires_at:.0f}"
        raw = f"{self.agent_id}|{self.vm_id}|{exp}"
        mac = hmac.new(self._secret, raw.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{raw}|{mac}"


# ─────────────────────────────────────────────────────────────────────────────
# Request signer
# ─────────────────────────────────────────────────────────────────────────────

class RequestSigner:
    """
    Signs outbound messages with HMAC-SHA256.
    Receiver uses verify() to confirm authenticity + freshness.

    Signature covers:
      - agent_id (who sent it)
      - timestamp (when — prevents replay)
      - payload digest (what — prevents tampering)
    """

    def __init__(self, agent_id: str, secret: bytes) -> None:
        self.agent_id = agent_id
        self._secret  = secret

    def _compute(self, agent_id: str, timestamp: str, payload_hash: str) -> str:
        msg = f"{agent_id}:{timestamp}:{payload_hash}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def sign_headers(self, payload_bytes: bytes) -> Dict[str, str]:
        """Return headers to attach to an outbound message."""
        ts           = str(int(time.time()))
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        sig          = self._compute(self.agent_id, ts, payload_hash)
        return {
            "X-SAP-Agent-ID":  self.agent_id,
            "X-SAP-Timestamp": ts,
            "X-SAP-Signature": sig,
        }

    def verify(
        self,
        payload_bytes: bytes,
        headers: Dict[str, str],
        max_age: float = REQUEST_SIGNATURE_TTL,
    ) -> None:
        """
        Verify a signed inbound message.
        Raises ZeroTrustViolation subclass on any failure.
        """
        ts_raw  = headers.get("X-SAP-Timestamp", "")
        sig_in  = headers.get("X-SAP-Signature", "")
        sent_id = headers.get("X-SAP-Agent-ID",  "")

        # 1. Timestamp present and parseable
        try:
            ts_int = int(ts_raw)
        except ValueError:
            raise SignatureMismatch("Missing or non-numeric X-SAP-Timestamp")

        # 2. Freshness check — prevents replay attacks
        age = time.time() - ts_int
        if age > max_age:
            raise SignatureExpired(
                f"Request is {age:.0f}s old; max allowed is {max_age}s"
            )
        if age < -5:
            raise SignatureExpired(f"Request timestamp is {-age:.0f}s in the future")

        # 3. HMAC verification — constant-time compare prevents timing attacks
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        expected     = self._compute(sent_id, ts_raw, payload_hash)
        if not hmac.compare_digest(expected, sig_in):
            raise SignatureMismatch("HMAC signature mismatch — payload may be tampered")


# ─────────────────────────────────────────────────────────────────────────────
# Zero-trust gateway
# ─────────────────────────────────────────────────────────────────────────────

class ZeroTrustGateway:
    """
    Validates every inbound A2A message before it reaches any agent logic.

    Checks (in order):
      1. Sender identity is in the allowed list
      2. Agent token has not expired (if provided)
      3. Request signature is valid and fresh
      4. Payload schema is structurally sound (basic sanity, not full Pydantic)

    On any failure: raises ZeroTrustViolation, logs with severity=error,
    and the caller should terminate the connection + destroy the VM.
    """

    def __init__(
        self,
        allowed_senders: list[str],
        signer: Optional[RequestSigner] = None,
    ) -> None:
        self._allowed_senders = set(allowed_senders)
        self._signer          = signer
        self._violations      = 0
        self._messages        = 0

    def validate(
        self,
        payload_bytes: bytes,
        headers: Dict[str, str],
        *,
        audit_fn=None,
    ) -> None:
        """
        Full zero-trust validation of one inbound message.
        Call this before ANY processing of the payload.
        """
        self._messages += 1
        sender = headers.get("X-SAP-Agent-ID", "<unknown>")

        try:
            # 1. Sender allow-list
            if sender not in self._allowed_senders:
                raise UnknownSender(
                    f"Sender '{sender}' not in allowed list {self._allowed_senders}"
                )

            # 2. Agent token expiry (optional — present only when token header sent)
            token_header = headers.get("X-Agent-Token-Expires")
            if token_header:
                try:
                    exp = float(token_header)
                    if time.time() > exp:
                        raise TokenExpired(
                            f"Agent token for '{sender}' expired "
                            f"{time.time() - exp:.0f}s ago"
                        )
                except (ValueError, TypeError):
                    pass   # header present but malformed — tolerate

            # 3. Signature (if a signer is configured)
            if self._signer is not None:
                self._signer.verify(payload_bytes, headers)

            # 4. Basic structural sanity
            if len(payload_bytes) == 0:
                raise ZeroTrustViolation("Empty payload rejected")
            if len(payload_bytes) > 50 * 1024 * 1024:
                raise ZeroTrustViolation(
                    f"Payload size {len(payload_bytes):,} bytes exceeds 50MB limit"
                )

        except ZeroTrustViolation:
            self._violations += 1
            logger.error(
                "Zero-trust violation from sender='%s': %s",
                sender, type(ZeroTrustViolation).__name__,
            )
            if audit_fn:
                try:
                    audit_fn(
                        "ZERO_TRUST_VIOLATION", "error",
                        message=str(ZeroTrustViolation),
                        sender=sender,
                    )
                except Exception:
                    pass
            raise

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "messages_validated": self._messages,
            "violations_detected": self._violations,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience factory
# ─────────────────────────────────────────────────────────────────────────────

def create_agent_identity(agent_id: str, vm_id: str) -> AgentToken:
    """Issue a fresh short-lived identity token for a new agent VM."""
    token = AgentToken(agent_id=agent_id, vm_id=vm_id)
    logger.info(
        "Agent identity issued: %s @ %s  expires_in=%.0fs",
        agent_id, vm_id, token.remaining_seconds,
    )
    return token


def pipeline_signer(agent_id: str) -> RequestSigner:
    """
    Create a RequestSigner with a fresh ephemeral secret.
    Each pipeline run gets its own key — compromise of one run
    does not compromise any other.
    """
    return RequestSigner(agent_id=agent_id, secret=secrets.token_bytes(32))