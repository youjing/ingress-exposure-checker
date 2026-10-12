from iec.models import ScanResult, AuthStatus, SEVERITY_RANK


def render_markdown(results: list[ScanResult]) -> str:
    from collections import Counter
    counts = Counter(r.auth_status for r in results)
    lines = [
        "# Ingress Exposure Scan Report",
        "",
        f"**Total endpoints scanned:** {len(results)}",
        "",
        f"- **CRITICAL (EXPOSED_NO_AUTH):** {counts.get(AuthStatus.EXPOSED_NO_AUTH, 0)}",
        f"- **HIGH (EXPOSED_DEFAULT_CREDS):** {counts.get(AuthStatus.EXPOSED_DEFAULT_CREDS, 0)}",
        "",
        "| Severity | Namespace | Endpoint | Middleware | Status | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(results, key=lambda x: SEVERITY_RANK[x.severity]):
        evidence = "; ".join(r.evidence[:3]).replace("|", "/") or "-"
        ns = (r.target.namespace or "-").replace("|", "/")
        lines.append(f"| {r.severity.value} | {ns} | `{r.target.url}` | {r.middleware or '-'} | {r.auth_status.value} | {evidence} |")
    return "\n".join(lines)
