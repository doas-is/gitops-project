#!/usr/bin/env python3
"""
Launch the Secure Analysis Platform with monitoring dashboard.

Usage:
  python run.py             # Start monitor on port 8000
  python run.py --analyze   # Run analysis + monitor

  # Generate 5000 synthetic IR samples and fine-tune
    python -m src.analyzer.model_trainer --samples 5000 --epochs-p1 10 --epochs-p2 5
"""
import argparse
import asyncio
import os
import sys

# Ensure src is importable
sys.path.insert(0, os.path.dirname(__file__))

os.environ.setdefault("KMS_LOCAL", "true")


def run_monitor():
    """Start the monitoring dashboard."""
    import uvicorn
    from ui.monitor import app

    port = int(os.getenv("MONITOR_PORT", "8000"))
    host = os.getenv("MONITOR_HOST", "0.0.0.0")

    print(f"Secure Analysis Platform Monitor")
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