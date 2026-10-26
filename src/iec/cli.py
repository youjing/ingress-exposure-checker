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
    p.add_argument(
        "--direct", action="store_true",
        help="Bypass system/env HTTP proxy and probe targets directly",
    )
    p.add_argument(
        "--slack-webhook", default=None, metavar="URL",
        help="Post CRITICAL/HIGH findings to this Slack Incoming Webhook",
    )
    return p


async def _run(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                               SpinnerColumn, TaskProgressColumn,
                               TextColumn, TimeElapsedColumn)

    if args.url:
        from iec.input import _normalize_url
        targets = [Target(url=_normalize_url(args.url))]
        print(f"扫描单目标: {targets[0].url}")
    else:
        if not args.input:
            print("error: either a input file or --url is required", file=sys.stderr)
            return 3
        targets = parse_targets(Path(args.input))
        print(f"已加载 {len(targets)} 个目标 (来自 {args.input})")

    results: list = []

    def on_found(result) -> None:
        results.append(result)

    console = Console()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("准备扫描...", total=len(targets))

        def on_done(t) -> None:
            progress.update(task_id, description=f"[dim]{t.url[:64]}[/dim]")
            progress.advance(task_id)

        scanned = await scan_all(
            targets,
            concurrency=args.concurrency,
            timeout=args.timeout,
            verify_tls=not args.insecure_tls,
            trust_env=not args.direct,
            on_found=on_found,
            on_done=on_done,
        )

    render_terminal_summary(scanned)

    if not args.no_report:
        Path(args.output_html).write_text(render_html(scanned), encoding="utf-8")
        Path(args.output_md).write_text(render_markdown(scanned), encoding="utf-8")
        print(f"\nHTML 报告: {args.output_html}")
        print(f"Markdown 报告: {args.output_md}")

    if args.slack_webhook:
        from iec.report.slack import build_slack_payload, env_name_from_file, send_slack
        env_name = (env_name_from_file(args.input)
                    if args.input else f"single-{Target(url=args.url).url.split('//')[-1]}")
        payload = build_slack_payload(scanned, env_name,
                                      total_scanned=len(scanned),
                                      report_path=args.output_html)
        ok, msg = await send_slack(args.slack_webhook, payload)
        mark = "✓" if ok else "✗"
        print(f"Slack 告警: {mark} {msg}")

    critical = sum(1 for r in scanned if r.auth_status.value == "exposed_no_auth")
    high = sum(1 for r in scanned if r.auth_status.value == "exposed_default_creds")
    return 2 if critical else (1 if high else 0)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        exit_code = asyncio.run(_run(args))
    except FileNotFoundError as e:
        print(f"\n[错误] {e}", file=sys.stderr)
        sys.exit(3)
    except ValueError as e:
        print(f"\n[错误] 输入格式问题: {e}", file=sys.stderr)
        sys.exit(3)
    except KeyboardInterrupt:
        print("\n已中断扫描", file=sys.stderr)
        sys.exit(130)
    sys.exit(exit_code)
