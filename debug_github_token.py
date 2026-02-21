#!/usr/bin/env python3
"""
script to be ran on project root to diagnose the 401 error when repo_cloner.py tries to access the GitHub API.
It checks for common issues with the token and performs live API tests to verify its validity and permissions.
"""
import asyncio
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

TOKEN    = os.getenv("GITHUB_TOKEN", "").strip()
REPO_URL = os.getenv("GITHUB_REPO_URL", "https://github.com/doas-is/synapse-2").strip()

# ── Parse owner/repo ─────────────────────────────────────────────────────────
from urllib.parse import urlparse
parts = urlparse(REPO_URL).path.strip("/").removesuffix(".git").split("/")
OWNER, REPO = (parts[0], parts[1]) if len(parts) >= 2 else ("doas-is", "synapse-2")

print("=" * 60)
print("GitHub Token Diagnostics")
print("=" * 60)

# ── 1. Token presence ─────────────────────────────────────────────────────────
if not TOKEN:
    print("❌  GITHUB_TOKEN is not set in .env")
    sys.exit(1)

fmt = TOKEN[:4] + "..." + TOKEN[-4:] if len(TOKEN) > 8 else "***"
print(f"✓   Token found:  {fmt}  ({len(TOKEN)} chars)")

# ── 2. Token format ───────────────────────────────────────────────────────────
if TOKEN.startswith("ghp_"):
    print("✓   Format:       Classic PAT (ghp_)")
elif TOKEN.startswith("github_pat_"):
    print("⚠   Format:       Fine-grained PAT (github_pat_) — needs Contents:Read scope")
elif TOKEN.startswith("gho_"):
    print("⚠   Format:       OAuth token (gho_) — may lack repo scope")
else:
    print(f"⚠   Format:       Unknown prefix — may be malformed")

# ── 3. Whitespace / newline contamination ────────────────────────────────────
raw = os.getenv("GITHUB_TOKEN", "")
if raw != raw.strip():
    print("❌  Token has leading/trailing whitespace in .env — fix that first")
    sys.exit(1)
if "\n" in raw or "\r" in raw:
    print("❌  Token contains newline character — .env line is broken across lines")
    sys.exit(1)
print("✓   No whitespace contamination")

# ── 4. Live API tests ─────────────────────────────────────────────────────────
try:
    import aiohttp
except ImportError:
    print("❌  aiohttp not installed: pip install aiohttp")
    sys.exit(1)


async def run():
    connector = aiohttp.TCPConnector(ssl=True)
    async with aiohttp.ClientSession(connector=connector) as s:

        # ── Test A: Bearer (new format) ───────────────────────────────────
        print("\n── Test A: Authorization: Bearer <token> ──────────────────")
        async with s.get(
            "https://api.github.com/rate_limit",
            headers={
                "Authorization":        f"Bearer {TOKEN}",
                "Accept":               "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent":           "debug-script/1.0",
            },
        ) as r:
            body = await r.json()
            if r.status == 200:
                core = body.get("resources", {}).get("core", {})
                print(f"✓   Status 200 — rate limit: {core.get('remaining')}/{core.get('limit')}")
                bearer_ok = True
            elif r.status == 401:
                print(f"❌  Status 401 — {body.get('message', '')}")
                bearer_ok = False
            else:
                print(f"⚠   Status {r.status} — {body}")
                bearer_ok = False

        # ── Test B: token (old format) ────────────────────────────────────
        print("\n── Test B: Authorization: token <token> ───────────────────")
        async with s.get(
            "https://api.github.com/rate_limit",
            headers={
                "Authorization": f"token {TOKEN}",
                "Accept":        "application/vnd.github.v3+json",
                "User-Agent":    "debug-script/1.0",
            },
        ) as r:
            body = await r.json()
            if r.status == 200:
                core = body.get("resources", {}).get("core", {})
                print(f"✓   Status 200 — rate limit: {core.get('remaining')}/{core.get('limit')}")
                token_ok = True
            else:
                print(f"❌  Status {r.status} — {body.get('message', '')}")
                token_ok = False

        # ── Test C: Repo access ───────────────────────────────────────────
        print(f"\n── Test C: Repo access ({OWNER}/{REPO}) ─────────────────────")
        header = f"Bearer {TOKEN}" if bearer_ok else f"token {TOKEN}"
        async with s.get(
            f"https://api.github.com/repos/{OWNER}/{REPO}",
            headers={
                "Authorization":        header,
                "Accept":               "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent":           "debug-script/1.0",
            },
        ) as r:
            body = await r.json()
            if r.status == 200:
                private = body.get("private", False)
                print(f"✓   Repo found — private={private}, default_branch={body.get('default_branch')}")
            elif r.status == 404:
                print(f"❌  404 — repo not found or token has no access")
                print(f"    Is '{OWNER}/{REPO}' private? Token needs 'repo' scope.")
            elif r.status == 401:
                print(f"❌  401 — {body.get('message')}")
            else:
                print(f"⚠   {r.status} — {body.get('message', body)}")

        # ── Test D: No-auth baseline ──────────────────────────────────────
        print("\n── Test D: Unauthenticated baseline ───────────────────────")
        async with s.get(
            "https://api.github.com/rate_limit",
            headers={"User-Agent": "debug-script/1.0"},
        ) as r:
            body = await r.json()
            core = body.get("resources", {}).get("core", {})
            print(f"   Unauthenticated limit: {core.get('limit')}/hr  "
                  f"(if your token hits 401, check the token itself)")

        # ── Summary ───────────────────────────────────────────────────────
        print("\n" + "=" * 60)
        if bearer_ok:
            print("✅  RESULT: Bearer auth works — update repo_cloner.py:")
            print('    headers["Authorization"] = f"Bearer {TOKEN}"')
        elif token_ok:
            print("✅  RESULT: Old 'token' format works but Bearer doesn't")
            print("    This is unusual for a ghp_ token. Token may be in a")
            print("    legacy state. Try regenerating it.")
        else:
            print("❌  RESULT: Both auth formats fail → token is invalid")
            print()
            print("   Fix: generate a new token at")
            print("   https://github.com/settings/tokens/new")
            print("   → select 'repo' scope → copy → paste into .env")
            print()
            print("   Then restart: python run.py")

asyncio.run(run())