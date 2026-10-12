from iec.models import ScanResult, AuthStatus, Severity, SEVERITY_RANK

COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.OK: "green",
    Severity.INFO: "dim",
}


def render_terminal_summary(results: list[ScanResult]) -> None:
    from rich.console import Console
    from rich.table import Table
    from collections import Counter

    console = Console()
    counts = Counter(r.auth_status for r in results)
    console.print(f"\n[bold]Total endpoints scanned:[/bold] {len(results)}")
    console.print(f"[bold red]  EXPOSED_NO_AUTH (CRITICAL):[/bold red] {counts.get(AuthStatus.EXPOSED_NO_AUTH, 0)}")
    console.print(f"[bold yellow]  EXPOSED_DEFAULT_CREDS (HIGH):[/bold yellow] {counts.get(AuthStatus.EXPOSED_DEFAULT_CREDS, 0)}")

    table = Table(title="Findings (sorted by severity)")
    table.add_column("Severity")
    table.add_column("Endpoint")
    table.add_column("Middleware")
    table.add_column("Status")
    table.add_column("Evidence")
    for r in sorted(results, key=lambda x: SEVERITY_RANK[x.severity]):
        table.add_row(
            f"[{COLORS[r.severity]}]{r.severity.value}[/{COLORS[r.severity]}]",
            r.target.url,
            r.middleware or "-",
            r.auth_status.value,
            "; ".join(r.evidence[:2]) or "-",
        )
    console.print(table)
