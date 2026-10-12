from iec.models import ScanResult, AuthStatus, Severity, SEVERITY_RANK, SEVERITY_ZH

COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.OK: "green",
    Severity.INFO: "dim",
}

SEVERITY_ICONS_ZH = {
    "critical": "🔴 严重漏洞",
    "high": "🟠 高危漏洞",
    "info": "⚪ 信息 / 待确认",
    "ok": "🟢 正常",
}


def render_terminal_summary(results: list[ScanResult]) -> None:
    from rich.console import Console
    from rich.table import Table
    from collections import Counter

    console = Console()
    counts = Counter(r.auth_status for r in results)
    console.print(f"\n[bold]扫描目标总数:[/bold] {len(results)}")
    console.print(f"[bold red]  严重 — 无需登录即可访问:[/bold red] {counts.get(AuthStatus.EXPOSED_NO_AUTH, 0)}")
    console.print(f"[bold yellow]  高危 — 默认凭据可登录:[/bold yellow] {counts.get(AuthStatus.EXPOSED_DEFAULT_CREDS, 0)}")

    table = Table(title="扫描结果摘要(按严重级别排序)")
    table.add_column("级别")
    table.add_column("公网可达")
    table.add_column("命名空间")
    table.add_column("目标")
    table.add_column("中间件")
    table.add_column("判定")
    for r in sorted(results, key=lambda x: SEVERITY_RANK[x.severity]):
        reach = "[green]✅ 可达[/green]" if r.reachable else "[red]❌ 不可达[/red]"
        table.add_row(
            f"[{COLORS[r.severity]}]{r.severity_zh}[/{COLORS[r.severity]}]",
            reach,
            r.target.namespace or "-",
            r.target.url,
            r.middleware or "-",
            r.status_zh,
        )
    console.print(table)

    # ---------- 详细测试报告 ----------
    console.print("\n[bold]详细测试报告[/bold]\n")
    for key, icon in (("critical", "🔴 严重漏洞"), ("high", "🟠 高危漏洞"),
                      ("info", "⚪ 信息 / 待确认"), ("ok", "🟢 正常")):
        group = [r for r in results if r.severity.value == key]
        if not group:
            continue
        console.print(f"[bold]{icon}({len(group)} 项)[/bold]")
        for r in sorted(group, key=lambda x: x.target.namespace):
            title = f"[{r.target.namespace or '-'} / {r.target.name or '-'}] {r.target.url}"
            console.print(f"  [underline]{title}[/underline]")
            console.print(f"    中间件: {r.middleware or '未识别'} | 判定: {r.status_zh}")
            if r.error:
                console.print(f"    错误: {r.error}")
            for d in r.details:
                mark = "[bold red]✗[/bold red]" if d.vulnerable else "[green]✓[/green]"
                console.print(f"    {mark} {d.name}: {d.description}")
                console.print(f"        凭据: {d.credentials} | 请求: {d.request}")
                if d.response:
                    console.print(f"        响应: {d.response}")
                result_color = "bold red" if d.vulnerable else "green"
                console.print(f"        结论: [{result_color}]{d.result}[/{result_color}]")
            console.print()
