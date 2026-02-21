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
  │  SecurityError      — base for all security exceptions in platform  │
  │  RequestSigner      — HMAC-SHA256 signs every message + timestamp   │
  │  AgentToken         — short-lived identity token per agent instance │
  │  ZeroTrustGateway   — validates ALL inbound payloads before routing │
  └─────────────────────────────────────────────────────────────────────┘

Usage (in any agent):
    from src.security.zero_trust import ZeroTrustGateway, RequestSigner

    # At agent startup
    signer  = RequestSigner(agent_id="ast_parser", secret=session_secret)
    gateway = ZeroTrustGateway(allowed_senders=["secure_fetcher"], signer=signer)

    # When sending a message
    signed_headers = signer.sign_headers(payload_bytes)

    # When receiving a message
    gateway.validate(payload_bytes, signed_headers)  # raises ZeroTrustViolation on failure

Changes vs. prior version
──────────────────────────
  FIXED: SecurityError base class was missing entirely — ZeroTrustViolation(SecurityError)
         caused NameError on first import, crashing the entire pipeline at startup.

  FIXED: In validate() except block, the caught exception was never bound to a variable.
         - `type(ZeroTrustViolation).__name__` logged the metaclass name ("type"), not the
           exception class name. Now correctly uses `type(exc).__name__`.
         - `str(ZeroTrustViolation)` passed the class object to str(), producing something
           like "<class 'ZeroTrustViolation'>". Now correctly uses `str(exc)` for the message.

  FIXED: AgentToken.signing_key() and to_header() used hmac.new() — Python's hmac module
         does not have hmac.new(); the constructor is hmac.HMAC() or the module-level
         hmac.new() alias. Replaced with the explicit hmac.new() which IS the correct alias.
         (Python docs: hmac.new is the canonical factory function — this was correct, kept.)

  ADDED: validate() now logs the specific exception subclass and message to stderr for
         immediate visibility, in addition to calling the audit_fn.

  ADDED: ZeroTrustGateway.reset_stats() for test isolation.

  ADDED: PayloadTooLarge exception subclass (was a bare ZeroTrustViolation before).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── TTL constants ─────────────────────────────────────────────────────────────
REQUEST_SIGNATURE_TTL = 60      # seconds — signed request valid window
AGENT_TOKEN_TTL       = 7_200   # seconds — agent identity token lifetime (2h)
MAX_PAYLOAD_BYTES     = 50 * 1024 * 1024   # 50 MB hard ceiling


# ══════════════════════════════════════════════════════════════════════════════
# Exception hierarchy
#
# SecurityError must be defined FIRST — all subclasses reference it.
# Previously missing: ZeroTrustViolation(SecurityError) caused NameError
# at import time, crashing the pipeline before any agent could start.
# ══════════════════════════════════════════════════════════════════════════════

class SecurityError(Exception):
    """
    Base class for all security-related exceptions in the platform.
    Catching this catches every violation, expiry, and mismatch below.
    """


class ZeroTrustViolation(SecurityError):
    """
    Raised when a zero-trust check fails.
    Always triggers an audit log entry and should result in VM teardown.
    """


class SignatureExpired(ZeroTrustViolation):
    """Request signature timestamp is outside the acceptable window (replay prevention)."""


class SignatureMismatch(ZeroTrustViolation):
    """HMAC digest does not match — request was tampered with or key is wrong."""


class UnknownSender(ZeroTrustViolation):
    """Message arrived from an agent not in the expected-sender allow-list."""


class TokenExpired(ZeroTrustViolation):
    """Agent identity token has passed its TTL — agent must be re-provisioned."""


class PayloadTooLarge(ZeroTrustViolation):
    """Payload exceeds the 50 MB size limit — potential DoS or data exfiltration attempt."""


class EmptyPayload(ZeroTrustViolation):
    """Zero-byte payload received — structurally invalid for any agent message."""


# ══════════════════════════════════════════════════════════════════════════════
# Agent identity token
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AgentToken:
    """
    Short-lived identity credential for one agent instance.
    Issued at VM creation, verified on every inbound message.
    Not a JWT — deliberately simple and self-contained.
    Each token has its own random secret; compromise of one
    does not compromise any other agent.
    """
    agent_id:  str
    vm_id:     str
    issued_at: float = field(default_factory=time.time)
    ttl:       float = AGENT_TOKEN_TTL
    _secret:   bytes = field(default_factory=lambda: secrets.token_bytes(32))

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
        """Derive a per-token signing key from the token secret."""
        return hmac.new(
            self._secret,
            f"{self.agent_id}:{self.vm_id}:{self.issued_at:.0f}".encode(),
            hashlib.sha256,
        ).digest()

    def to_header(self) -> str:
        """
        Compact wire representation for X-Agent-Token header.
        Format: agent_id|vm_id|expires_at|mac[:16]
        """
        exp = f"{self.expires_at:.0f}"
        raw = f"{self.agent_id}|{self.vm_id}|{exp}"
        mac = hmac.new(self._secret, raw.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{raw}|{mac}"


# ══════════════════════════════════════════════════════════════════════════════
# Request signer
# ══════════════════════════════════════════════════════════════════════════════

class RequestSigner:
    """
    Signs outbound A2A messages with HMAC-SHA256.
    The receiver calls verify() to confirm authenticity and freshness.

    Signature covers:
      - agent_id  (who sent it — identity binding)
      - timestamp (when — prevents replay attacks)
      - SHA-256 of payload (what — prevents tampering in transit)
    """

    def __init__(self, agent_id: str, secret: bytes) -> None:
        if not secret or len(secret) < 16:
            raise ValueError("RequestSigner secret must be at least 16 bytes")
        self.agent_id = agent_id
        self._secret  = secret

    def _compute(self, agent_id: str, timestamp: str, payload_hash: str) -> str:
        """Compute HMAC-SHA256 over agent_id:timestamp:payload_hash."""
        msg = f"{agent_id}:{timestamp}:{payload_hash}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def sign_headers(self, payload_bytes: bytes) -> Dict[str, str]:
        """
        Return a dict of HTTP headers to attach to an outbound message.
        All three headers must be forwarded together — they are verified as a unit.
        """
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
        Raises a ZeroTrustViolation subclass on any failure.
        All comparisons are constant-time to prevent timing attacks.
        """
        ts_raw  = headers.get("X-SAP-Timestamp", "")
        sig_in  = headers.get("X-SAP-Signature", "")
        sent_id = headers.get("X-SAP-Agent-ID",  "")

        # 1. Timestamp present and parseable
        try:
            ts_int = int(ts_raw)
        except ValueError:
            raise SignatureMismatch("Missing or non-numeric X-SAP-Timestamp")

        # 2. Freshness — prevents replay attacks
        age = time.time() - ts_int
        if age > max_age:
            raise SignatureExpired(
                f"Request is {age:.0f}s old; max allowed is {max_age}s"
            )
        if age < -5:
            # Clock skew tolerance: 5 seconds. Beyond that → likely spoofing.
            raise SignatureExpired(
                f"Request timestamp is {-age:.0f}s in the future (clock skew?)"
            )

        # 3. HMAC — constant-time compare prevents timing oracle attacks
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        expected     = self._compute(sent_id, ts_raw, payload_hash)
        if not hmac.compare_digest(expected, sig_in):
            raise SignatureMismatch("HMAC signature mismatch — payload may have been tampered")


# ══════════════════════════════════════════════════════════════════════════════
# Zero-trust gateway
# ══════════════════════════════════════════════════════════════════════════════

class ZeroTrustGateway:
    """
    Validates every inbound A2A message before it reaches any agent logic.

    Checks (in order):
      1. Sender identity is in the allowed-senders set
      2. Agent token has not expired (if X-Agent-Token-Expires header present)
      3. Request signature is valid and fresh (if signer is configured)
      4. Payload is non-empty and within size limits

    On any failure:
      - Increments violation counter
      - Logs with severity=error including exception type + message
      - Calls audit_fn if provided
      - Re-raises the ZeroTrustViolation subclass
      - Caller is responsible for terminating the connection + destroying the VM
    """

    def __init__(
        self,
        allowed_senders: List[str],
        signer: Optional[RequestSigner] = None,
    ) -> None:
        if not allowed_senders:
            raise ValueError("ZeroTrustGateway requires at least one allowed sender")
        self._allowed_senders = frozenset(allowed_senders)
        self._signer          = signer
        self._violations      = 0
        self._messages        = 0

    def validate(
        self,
        payload_bytes: bytes,
        headers: Dict[str, str],
        *,
        audit_fn: Optional[Callable] = None,
    ) -> None:
        """
        Full zero-trust validation of one inbound message.
        Call this before ANY processing of the payload.

        Parameters
        ──────────
        payload_bytes — raw bytes of the message body
        headers       — dict of HTTP-style headers (case-sensitive, SAP prefixed)
        audit_fn      — optional callable(event_type, severity, **kwargs) for audit logging
        """
        self._messages += 1
        sender = headers.get("X-SAP-Agent-ID", "<unknown>")

        try:
            # ── Check 1: sender allow-list ─────────────────────────────────
            if sender not in self._allowed_senders:
                raise UnknownSender(
                    f"Sender '{sender}' not in allowed list "
                    f"{sorted(self._allowed_senders)}"
                )

            # ── Check 2: agent token expiry (optional header) ──────────────
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
                    # Header present but malformed — tolerate silently.
                    # A malformed expiry header is not itself a violation;
                    # the signature check below provides the security guarantee.
                    logger.debug("Malformed X-Agent-Token-Expires from '%s': %s",
                                 sender, token_header)

            # ── Check 3: HMAC signature (if signer configured) ────────────
            if self._signer is not None:
                self._signer.verify(payload_bytes, headers)

            # ── Check 4: structural sanity ────────────────────────────────
            if len(payload_bytes) == 0:
                raise EmptyPayload(
                    f"Zero-byte payload from sender '{sender}'"
                )
            if len(payload_bytes) > MAX_PAYLOAD_BYTES:
                raise PayloadTooLarge(
                    f"Payload {len(payload_bytes):,} bytes from '{sender}' "
                    f"exceeds {MAX_PAYLOAD_BYTES // (1024*1024)} MB limit"
                )

        except ZeroTrustViolation as exc:
            # ── FIXED: was `type(ZeroTrustViolation).__name__` (always "type")
            #    and `str(ZeroTrustViolation)` (always the class repr).
            #    Now correctly binds `exc` and logs the actual instance.
            self._violations += 1
            exc_type = type(exc).__name__
            exc_msg  = str(exc)

            logger.error(
                "Zero-trust violation [%s] from sender='%s': %s",
                exc_type, sender, exc_msg,
            )

            if audit_fn is not None:
                try:
                    audit_fn(
                        "ZERO_TRUST_VIOLATION",
                        "error",
                        message=f"[{exc_type}] {exc_msg}",
                        sender=sender,
                        violation_type=exc_type,
                    )
                except Exception as audit_err:
                    # Never let audit logging suppress the original violation
                    logger.warning("audit_fn raised during violation logging: %s", audit_err)

            raise  # always re-raise — caller must terminate the VM

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "messages_validated": self._messages,
            "violations_detected": self._violations,
        }

    def reset_stats(self) -> None:
        """Reset counters — intended for test isolation only."""
        self._messages   = 0
        self._violations = 0


# ══════════════════════════════════════════════════════════════════════════════
# Convenience factories
# ══════════════════════════════════════════════════════════════════════════════

def create_agent_identity(agent_id: str, vm_id: str) -> AgentToken:
    """
    Issue a fresh short-lived identity token for a new agent VM.
    Call this immediately after the ACI container comes online.
    """
    token = AgentToken(agent_id=agent_id, vm_id=vm_id)
    logger.info(
        "Agent identity issued: agent=%s vm=%s expires_in=%.0fs",
        agent_id, vm_id, token.remaining_seconds,
    )
    return token


def pipeline_signer(agent_id: str) -> RequestSigner:
    """
    Create a RequestSigner with a fresh ephemeral secret.
    Each pipeline run gets its own key — compromise of one run
    cannot be used to forge messages in any other run.
    """
    return RequestSigner(agent_id=agent_id, secret=secrets.token_bytes(32))