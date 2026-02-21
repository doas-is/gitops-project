"""
Secure Fetcher Agent

Responsibilities:
  - Fetch GitHub repository files via GitHub REST API (no full git clone)
  - Immediately encrypt each file in memory (AES-256-GCM)
  - Discard plaintext buffers — plaintext lifetime < 1ms
  - Stream encrypted payloads to the pipeline

Zero-trust additions:
  - Every request carries a request-scoped HMAC signature
  - Token validity is verified before any fetch begins (avoids 401 mid-run)
  - Exponential back-off + retry on transient errors
  - Rate-limit awareness: reads X-RateLimit-Remaining and pauses before exhaustion

Auth fix vs. prior version:
  - Fine-grained GitHub PATs (github_pat_*) require "Bearer <token>", NOT "token <token>"
  - Classic PATs (ghp_*) also accept "Bearer" — it is the safe universal form now
"""
from __future__ import annotations

import asyncio
import gc
import hashlib
import hmac
import logging
import os
import secrets
import time
from base64 import b64encode
from typing import AsyncGenerator, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from src.key_management import FileEncryptor, build_kms
from src.schemas.a2a_schemas import (
    AgentRole,
    EncryptedFilePayload,
    MessageType,
    create_header,
)

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".rb",
    ".cpp", ".c", ".h", ".hpp",
    ".cs", ".php", ".sh",
    ".yaml", ".yml", ".json", ".toml",
    ".ini", ".cfg",
})

MAX_FILE_SIZE    = 10 * 1024 * 1024
MAX_FILES        = 500
FETCH_TIMEOUT    = 30
RATE_LIMIT_SAFE  = 50        # pause when fewer than this requests remain
RETRY_ATTEMPTS   = 3
RETRY_BACKOFF    = [1.0, 2.0, 4.0]
GITHUB_API_BASE  = "https://api.github.com"


class GitHubAuthError(RuntimeError):
    """Token missing, invalid, or expired."""


class SecureFetcherAgent:
    """Fetches repository files via GitHub API and encrypts them immediately."""

    def __init__(
        self,
        mtls_config=None,
        parser_host: str = "localhost",
        parser_port: int = 8443,
        use_local_kms: bool = False,
    ) -> None:
        self.parser_host = parser_host
        self.parser_port = parser_port
        self.kms         = build_kms(use_local=use_local_kms)
        self.encryptor   = FileEncryptor(self.kms)
        self._github_token = os.getenv("GITHUB_TOKEN", "").strip()

        # Zero-trust: ephemeral per-session HMAC key for request signing
        self._session_key = secrets.token_bytes(32)

        self._stats: dict = {
            "files_fetched": 0,
            "files_encrypted": 0,
            "bytes_fetched": 0,
            "errors": 0,
            "rate_limit_pauses": 0,
        }

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _auth_headers(self) -> dict:
        """
        Build GitHub API request headers.

        FIX: Fine-grained PATs (github_pat_*) require 'Bearer <token>'.
             Classic PATs (ghp_*) also accept Bearer — universally safe.
             The old 'token <PAT>' format returns 401 for fine-grained tokens.
        """
        headers = {
            "Accept":               "application/vnd.github+json",
            "User-Agent":           "SecureAnalysisPlatform/2.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"
        return headers

    def _sign_request(self, path: str) -> str:
        """Zero-trust: HMAC-SHA256 signature over path+timestamp for audit logs."""
        ts  = str(int(time.time()))
        sig = hmac.new(self._session_key, f"{path}:{ts}".encode(), hashlib.sha256).hexdigest()
        return f"t={ts},sig={sig}"

    async def _validate_token(self, session: aiohttp.ClientSession) -> None:
        """
        Zero-trust: verify token is valid BEFORE starting any real fetch.
        Uses /rate_limit — cheap, no data, doesn't consume quota.
        Raises GitHubAuthError on 401/403 so we fail fast with a clear message.
        """
        if not self._github_token:
            logger.warning(
                "No GITHUB_TOKEN set — unauthenticated (60 req/hr limit, "
                "private repos will fail). Set GITHUB_TOKEN in .env."
            )
            return

        url = f"{GITHUB_API_BASE}/rate_limit"
        try:
            async with session.get(
                url,
                headers=self._auth_headers(),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 401:
                    body = await resp.text()
                    raise GitHubAuthError(
                        "GitHub token invalid (401 Unauthorized). "
                        "Check GITHUB_TOKEN in your .env file — it may be expired, "
                        "revoked, or incorrectly copied. "
                        f"GitHub said: {body[:300]}"
                    )
                if resp.status == 403:
                    raise GitHubAuthError(
                        "GitHub token forbidden (403). "
                        "The token lacks required scopes: "
                        "'repo' for classic PATs, or 'Contents: Read' for fine-grained PATs."
                    )
                data    = await resp.json()
                core    = data.get("resources", {}).get("core", {})
                remain  = core.get("remaining", "?")
                limit   = core.get("limit", "?")
                reset   = core.get("reset", 0)
                minutes = max(0, int(reset) - int(time.time())) // 60
                logger.info(
                    "GitHub token valid ✓  rate limit: %s/%s remaining, resets in ~%dm",
                    remain, limit, minutes,
                )
        except GitHubAuthError:
            raise
        except Exception as e:
            logger.warning("Token pre-validation failed (network?): %s", e)

    # ── URL parsing ───────────────────────────────────────────────────────────

    @staticmethod
    def _parse_repo_url(url: str) -> Tuple[str, str]:
        parsed = urlparse(url.strip())
        path   = parsed.path.strip("/").removesuffix(".git")
        parts  = [p for p in path.split("/") if p]
        if len(parts) < 2:
            raise ValueError(
                f"Cannot parse GitHub URL '{url}'. "
                "Expected format: https://github.com/owner/repo"
            )
        return parts[0], parts[1]

    # ── Rate limit guard ──────────────────────────────────────────────────────

    async def _guard_rate_limit(self, resp: aiohttp.ClientResponse) -> None:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset_at  = resp.headers.get("X-RateLimit-Reset")
        if not remaining:
            return
        try:
            if int(remaining) < RATE_LIMIT_SAFE:
                wait = min(max(0, int(reset_at or 0) - int(time.time()) + 2), 60)
                logger.warning("Rate limit low (%s remaining) — pausing %ds", remaining, wait)
                self._stats["rate_limit_pauses"] += 1
                if wait > 0:
                    await asyncio.sleep(wait)
        except ValueError:
            pass

    # ── File listing ──────────────────────────────────────────────────────────

    async def _list_repo_files(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str,
    ) -> List[dict]:
        """List eligible files via Git Trees API. Tries HEAD, main, master in order."""
        for ref in ("HEAD", "main", "master"):
            url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
            headers = {
                **self._auth_headers(),
                "X-SAP-Signature": self._sign_request(
                    f"/repos/{owner}/{repo}/git/trees/{ref}"
                ),
            }
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                await self._guard_rate_limit(resp)

                if resp.status == 404 and ref != "master":
                    continue

                if resp.status == 401:
                    raise GitHubAuthError(
                        f"GitHub 401 listing repo tree for {owner}/{repo}. "
                        "Token may be expired or lack repo/Contents:Read scope."
                    )
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(
                        f"GitHub API {resp.status} listing {owner}/{repo} "
                        f"(ref={ref}): {text[:300]}"
                    )

                data = await resp.json()

                if data.get("truncated"):
                    logger.warning(
                        "Tree truncated by GitHub (>100k items) — "
                        "only first batch will be analysed."
                    )

                files = []
                for item in data.get("tree", []):
                    if item.get("type") != "blob":
                        continue
                    path = item["path"]
                    ext  = os.path.splitext(path)[1].lower()
                    if ext not in ALLOWED_EXTENSIONS:
                        continue
                    if item.get("size", 0) > MAX_FILE_SIZE:
                        logger.info("Skipping large file: %s (%d B)", path, item["size"])
                        continue
                    files.append(item)
                    if len(files) >= MAX_FILES:
                        logger.warning("MAX_FILES=%d reached, truncating.", MAX_FILES)
                        break

                logger.info(
                    "Found %d eligible files in %s/%s (ref=%s)",
                    len(files), owner, repo, ref,
                )
                return files

        raise RuntimeError(
            f"Could not find any accessible branch (HEAD/main/master) "
            f"for {owner}/{repo}. Check the URL and token permissions."
        )

    # ── Single-file fetch ─────────────────────────────────────────────────────

    async def _fetch_file(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str,
        path: str,
    ) -> Optional[bytes]:
        """Fetch raw bytes with retry/back-off."""
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"
        headers = {
            **self._auth_headers(),
            # Raw media type → server sends file bytes directly (no base64)
            "Accept": "application/vnd.github.raw+json",
            "X-SAP-Signature": self._sign_request(
                f"/repos/{owner}/{repo}/contents/{path}"
            ),
        }

        for attempt in range(RETRY_ATTEMPTS):
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
                ) as resp:
                    await self._guard_rate_limit(resp)

                    if resp.status == 200:
                        return await resp.read()

                    if resp.status in (401, 403):
                        logger.error("Auth error %d on %s — skipping", resp.status, path)
                        return None

                    if resp.status == 404:
                        return None

                    # Transient — will retry
                    logger.warning(
                        "HTTP %d fetching %s (attempt %d/%d)",
                        resp.status, path, attempt + 1, RETRY_ATTEMPTS,
                    )

            except asyncio.TimeoutError:
                logger.warning(
                    "Timeout fetching %s (attempt %d/%d)", path, attempt + 1, RETRY_ATTEMPTS
                )
            except Exception as e:
                logger.warning(
                    "Error fetching %s: %s (attempt %d/%d)",
                    path, type(e).__name__, attempt + 1, RETRY_ATTEMPTS,
                )
                self._stats["errors"] += 1

            if attempt < RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_BACKOFF[attempt])

        return None

    # ── Main stream ───────────────────────────────────────────────────────────

    async def fetch_and_encrypt_stream(
        self,
        repo_url: str,
        task_id: str,
    ) -> AsyncGenerator[EncryptedFilePayload, None]:
        """
        Validate token → list files → fetch + encrypt each file → yield payload.
        Plaintext bytes exist only between fetch and encrypt; GC'd immediately after.
        """
        owner, repo = self._parse_repo_url(repo_url)
        logger.info("Fetch start: %s/%s  task=%s", owner, repo, task_id)

        connector = aiohttp.TCPConnector(
            ssl=True,
            limit=10,
            keepalive_timeout=0,   # zero-trust: no persistent connections
        )

        async with aiohttp.ClientSession(connector=connector) as session:
            # Zero-trust: fail fast if token is bad
            await self._validate_token(session)

            files = await self._list_repo_files(session, owner, repo)
            total = len(files)

            if total == 0:
                logger.warning(
                    "No files with supported extensions found in %s/%s. "
                    "Supported: %s", owner, repo, ", ".join(sorted(ALLOWED_EXTENSIONS))
                )
                return

            for idx, file_info in enumerate(files):
                path = file_info["path"]
                ext  = os.path.splitext(path)[1].lower()

                raw = await self._fetch_file(session, owner, repo, path)
                if raw is None:
                    continue

                self._stats["files_fetched"]  += 1
                self._stats["bytes_fetched"]  += len(raw)

                # ── Encrypt immediately — plaintext lives only in this block ──
                try:
                    enc = self.encryptor.encrypt(raw)
                    self._stats["files_encrypted"] += 1
                finally:
                    del raw
                    gc.collect()

                ct_hash = hashlib.sha256(enc.ciphertext).hexdigest()
                header  = create_header(
                    MessageType.ENCRYPTED_FILE_PAYLOAD,
                    AgentRole.SECURE_FETCHER,
                    AgentRole.AST_PARSER,
                    task_id,
                )

                yield EncryptedFilePayload(
                    header=header,
                    ciphertext_b64=enc.ciphertext_b64(),
                    nonce_b64=enc.nonce_b64(),
                    encrypted_dek_b64=enc.encrypted_dek_b64(),
                    kek_key_id=enc.kek_key_id,
                    file_extension=ext,
                    file_size_bytes=file_info.get("size", 0),
                    ciphertext_sha256=ct_hash,
                    file_index=idx,
                    total_files=total,
                )

        logger.info(
            "Fetch done: %d/%d files encrypted, %d errors, %d rate-limit pauses",
            self._stats["files_encrypted"], self._stats["files_fetched"],
            self._stats["errors"], self._stats["rate_limit_pauses"],
        )

    def get_stats(self) -> dict:
        return dict(self._stats)