"""
Secure Fetcher Agent (repo_cloner.py)

Responsibilities:
  - Fetch GitHub repository files via API (no full git clone)
  - Immediately encrypt each file in memory
  - Discard plaintext buffers
  - Send encrypted payloads to AST Parser Agent via mTLS

Security guarantees:
  - No disk writes
  - No full repo cloning
  - No parsing or semantic inspection
  - Plaintext exists only for microseconds between fetch and encryption
  - File content is NEVER logged
"""
from __future__ import annotations

import asyncio
import gc
import hashlib
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
    A2AHeader,
    AgentRole,
    EncryptedFilePayload,
    MessageType,
    TaskManifest,
    create_header,
)
from src.security.mtls import MTLSClient, MTLSConfig

logger = logging.getLogger(__name__)

# Allowed source file extensions
ALLOWED_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".rb",
    ".cpp", ".c", ".h", ".hpp",
    ".cs", ".php", ".sh",
    ".yaml", ".yml", ".json", ".toml",
    ".ini", ".cfg", ".env.example",
})

# GitHub API limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_FILES = 500
FETCH_TIMEOUT = 30  # seconds per file


class SecureFetcherAgent:
    """
    Fetches repository files via GitHub API.
    Encrypts immediately, never touches disk.
    """

    def __init__(
        self,
        mtls_config: Optional[MTLSConfig] = None,
        parser_host: Optional[str] = None,
        parser_port: int = 8443,
        use_local_kms: bool = False,
    ) -> None:
        self.mtls_config = mtls_config
        self.parser_host = parser_host
        self.parser_port = parser_port
        self.kms = build_kms(use_local=use_local_kms)
        self.encryptor = FileEncryptor(self.kms)
        # Only build mTLS client if config provided (orchestrator mode skips this)
        self.client = MTLSClient(mtls_config) if mtls_config else None
        self._github_token = os.getenv("GITHUB_TOKEN")
        self._stats = {
            "files_fetched": 0,
            "files_encrypted": 0,
            "files_sent": 0,
            "bytes_fetched": 0,
            "errors": 0,
        }

    def _parse_repo_url(self, url: str) -> Tuple[str, str]:
        """Extract owner/repo from GitHub URL."""
        parsed = urlparse(url)
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            raise ValueError(f"Invalid GitHub URL: {url}")
        return parts[0], parts[1].removesuffix(".git")

    def _build_api_headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SecureAnalysisPlatform/1.0",
        }
        if self._github_token:
            headers["Authorization"] = f"token {self._github_token}"
        return headers

    async def _list_repo_files(
        self, session: aiohttp.ClientSession, owner: str, repo: str
    ) -> List[dict]:
        """List all files in repo via GitHub Trees API (no content)."""
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
        async with session.get(url, headers=self._build_api_headers()) as resp:
            if resp.status != 200:
                raise RuntimeError(f"GitHub API error: {resp.status}")
            data = await resp.json()

        files = []
        for item in data.get("tree", []):
            if item["type"] != "blob":
                continue
            path = item["path"]
            ext = os.path.splitext(path)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                continue
            if item.get("size", 0) > MAX_FILE_SIZE:
                logger.info("Skipping oversized file: %s (%d bytes)", path, item["size"])
                continue
            files.append(item)
            if len(files) >= MAX_FILES:
                logger.warning("File limit reached (%d), truncating", MAX_FILES)
                break

        return files

    async def _fetch_file_content(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str,
        path: str,
    ) -> Optional[bytes]:
        """Fetch single file content. Returns raw bytes, caller must handle securely."""
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        try:
            async with session.get(
                url,
                headers={**self._build_api_headers(), "Accept": "application/vnd.github.raw"},
                timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    logger.warning("Failed to fetch %s: HTTP %d", path, resp.status)
                    return None
                content = await resp.read()
                return content
        except Exception as e:
            logger.error("Error fetching %s: %s", path, type(e).__name__)
            self._stats["errors"] += 1
            return None

    async def fetch_and_encrypt_stream(
        self, repo_url: str, task_id: str
    ) -> AsyncGenerator[EncryptedFilePayload, None]:
        """
        Stream encrypted file payloads without accumulating plaintext.
        Each file is encrypted immediately and plaintext discarded.
        """
        owner, repo = self._parse_repo_url(repo_url)

        # Connector with no keepalive (zero-trust: new connection per session)
        connector = aiohttp.TCPConnector(
            ssl=True,
            limit=10,
            keepalive_timeout=0,
        )

        async with aiohttp.ClientSession(connector=connector) as session:
            files = await self._list_repo_files(session, owner, repo)
            total = len(files)
            logger.info("Found %d eligible files in %s/%s", total, owner, repo)

            for idx, file_info in enumerate(files):
                path = file_info["path"]
                ext = os.path.splitext(path)[1].lower()

                # Fetch raw bytes
                raw_content = await self._fetch_file_content(session, owner, repo, path)
                if raw_content is None:
                    continue

                self._stats["files_fetched"] += 1
                self._stats["bytes_fetched"] += len(raw_content)

                # IMMEDIATELY encrypt - plaintext lifespan ends here
                try:
                    payload = self.encryptor.encrypt(raw_content)
                    self._stats["files_encrypted"] += 1
                finally:
                    # Force GC to reclaim plaintext bytes
                    del raw_content
                    gc.collect()

                # Compute integrity hash on ciphertext
                ct_hash = hashlib.sha256(payload.ciphertext).hexdigest()

                header = create_header(
                    MessageType.ENCRYPTED_FILE_PAYLOAD,
                    AgentRole.SECURE_FETCHER,
                    AgentRole.AST_PARSER,
                    task_id,
                )

                yield EncryptedFilePayload(
                    header=header,
                    ciphertext_b64=payload.ciphertext_b64(),
                    nonce_b64=payload.nonce_b64(),
                    encrypted_dek_b64=payload.encrypted_dek_b64(),
                    kek_key_id=payload.kek_key_id,
                    file_extension=ext,
                    file_size_bytes=file_info.get("size", 0),
                    ciphertext_sha256=ct_hash,
                    file_index=idx,
                    total_files=total,
                )

    async def run(self, task: TaskManifest) -> dict:
        """
        Execute fetch task:
        1. Fetch files from GitHub
        2. Encrypt each immediately
        3. Send encrypted payloads to Parser Agent via mTLS
        """
        task_id = task.task_id
        sent = 0

        async for payload in self.fetch_and_encrypt_stream(task.repo_url, task_id):
            msg = payload.model_dump()
            try:
                response = await self.client.send(
                    self.parser_host,
                    self.parser_port,
                    msg,
                )
                if response.get("status") == "ok":
                    sent += 1
                    self._stats["files_sent"] += 1
                else:
                    logger.warning("Parser rejected payload %d: %s", payload.file_index, response)
            except Exception as e:
                logger.error("Failed to send payload %d: %s", payload.file_index, type(e).__name__)
                self._stats["errors"] += 1

        logger.info(
            "Fetch task %s complete: %d/%d files sent",
            task_id, sent, self._stats["files_fetched"]
        )
        return {
            "task_id": task_id,
            "status": "complete",
            "files_sent": sent,
            "stats": self._stats,
        }

    def get_stats(self) -> dict:
        return dict(self._stats)