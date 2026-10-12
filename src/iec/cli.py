from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from iec import __version__
from iec.input import parse_targets
from iec.models import Target
from iec.report.html import render_html
from iec.report.markdown import render_markdown
from iec.report.terminal import render_terminal_summary
from iec.runner import scan_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iec",
        description=(
            "Scan publicly exposed Ingress endpoints for no-auth "
            "/ default-credential vulnerabilities."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "input", nargs="?", default=None,
        help="Path to TXT/CSV file listing endpoint URLs (or ingress table export)",
    )
    p.add_argument(
        "--url", default=None,
        help="Scan a single URL directly instead of reading from a file",
    )
    p.add_argument(
        "--authorized",
        action="store_true",
        required=True,
        help="Declare you have authorization to scan the listed targets.",
    )
    p.add_argument(
        "--output-html", default="report.html", help="HTML report output path"
    )
    p.add_argument(
        "--output-md", default="report.md", help="Markdown report output path"
    )
    p.add_argument(
        "--no-report", action="store_true",
        help="Skip writing HTML/Markdown report files (terminal output only)",
    )
    p.add_argument(
        "--concurrency", type=int, default=20, help="Global concurrency (default 20)"
    )
    p.add_argument(
        "--timeout", type=float, default=10.0, help="Per-request timeout in seconds"
    )
    p.add_argument(
        "--insecure-tls", action="store_true", help="Skip TLS certificate verification"
    )
    return p


async def _run(args: argparse.Namespace) -> int:
    if args.url:
        from iec.input import _normalize_url
        targets = [Target(url=_normalize_url(args.url))]
        print(f"Scanning single target: {targets[0].url}")
    else:
        if not args.input:
            print("error: either a input file or --url is required", file=sys.stderr)
            return 3
        targets = parse_targets(Path(args.input))
        print(f"Loaded {len(targets)} targets from {args.input}")

    results: list = []

    def on_found(result) -> None:
        results.append(result)

    scanned = await scan_all(
        targets,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verify_tls=not args.insecure_tls,
        on_found=on_found,
    )

    render_terminal_summary(scanned)

    if not args.no_report:
        Path(args.output_html).write_text(render_html(scanned), encoding="utf-8")
        Path(args.output_md).write_text(render_markdown(scanned), encoding="utf-8")
        print(f"\nHTML report: {args.output_html}")
        print(f"Markdown report: {args.output_md}")

    critical = sum(1 for r in scanned if r.auth_status.value == "exposed_no_auth")
    high = sum(1 for r in scanned if r.auth_status.value == "exposed_default_creds")
    return 2 if critical else (1 if high else 0)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    exit_code = asyncio.run(_run(args))
    sys.exit(exit_code)
