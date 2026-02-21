#!/usr/bin/env python3
"""
Launch the Secure Analysis Platform with monitoring dashboard.

Usage:
  python run.py             # Start monitor on port 8000
  python run.py --analyze   # Run analysis + monitor
"""
import argparse
import asyncio
import os
import sys

# Ensure src is importable
sys.path.insert(0, os.path.dirname(__file__))

# Load .env before anything else
from dotenv import load_dotenv
load_dotenv(override=False)  # override=False: real env vars take precedence
def _check_env() -> None:
    dry_run = os.getenv("AZURE_DEPLOY_DRY_RUN", "true").lower() == "true"
    kms_local = os.getenv("KMS_LOCAL", "true").lower() == "true"
    if not dry_run or not kms_local:
        required = [
            "AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID",
            "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
            "GITHUB_TOKEN",
        ]
        missing = [k for k in required if not os.getenv(k)]
        if missing:
            print(f"❌ Missing required env vars: {', '.join(missing)}")
            print("   Check your .env file.")
            sys.exit(1)
    acr = os.getenv("ACR_NAME")
    agent_image = os.getenv("AGENT_IMAGE", "")
    if acr and "azurecr.io" in agent_image:
        if not os.getenv("ACR_USERNAME") or not os.getenv("ACR_PASSWORD"):
            print("❌ ACR_NAME is set but ACR_USERNAME / ACR_PASSWORD are missing.")
            sys.exit(1)

_check_env()
os.environ.setdefault("KMS_LOCAL", "false")


def run_monitor():
    """Start the monitoring dashboard."""
    import uvicorn
    from ui.monitor import app

    port = int(os.getenv("MONITOR_PORT", "8000"))
    host = os.getenv("MONITOR_HOST", "0.0.0.0")

    print(f"🔒 Secure Analysis Platform Monitor")
    print(f"   Dashboard: http://localhost:{port}")
    print(f"   API Docs:  http://localhost:{port}/docs")
    print()

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,  # No access logs (security)
    )


def run_analysis(repo_url: str):
    """Run analysis from CLI."""
    from src.main import main as analysis_main
    os.environ["GITHUB_REPO_URL"] = repo_url
    asyncio.run(analysis_main())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Analysis Platform")
    parser.add_argument("--analyze", metavar="REPO_URL",
                        help="Analyze a GitHub repository")
    parser.add_argument("--monitor-only", action="store_true",
                        help="Start monitoring dashboard only")
    args = parser.parse_args()

    if args.analyze:
        run_analysis(args.analyze)
    else:
        run_monitor()