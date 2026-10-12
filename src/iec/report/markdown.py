from iec.models import ScanResult, AuthStatus, SEVERITY_RANK, SEVERITY_ZH

SEVERITY_ICONS = {
    "critical": "🔴 严重",
    "high": "🟠 高危",
    "info": "⚪ 信息",
    "ok": "🟢 正常",
}


def _escape(s: str) -> str:
    return s.replace("|", "/").replace("\n", " ")


def render_markdown(results: list[ScanResult]) -> str:
    from collections import Counter
    counts = Counter(r.auth_status for r in results)
    lines = [
        "# Ingress 暴露面安全扫描报告",
        "",
        f"**扫描目标总数:** {len(results)}",
        "",
        f"- **严重 (无需登录即可访问):** {counts.get(AuthStatus.EXPOSED_NO_AUTH, 0)}",
        f"- **高危 (默认凭据可登录):** {counts.get(AuthStatus.EXPOSED_DEFAULT_CREDS, 0)}",
        "",
        "## 摘要",
        "",
        "| 严重级别 | 公网可达 | 命名空间 | 目标 | 中间件 | 状态 | 证据 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in sorted(results, key=lambda x: SEVERITY_RANK[x.severity]):
        evidence = "; ".join(r.evidence[:3]).replace("|", "/") or "-"
        ns = (r.target.namespace or "-").replace("|", "/")
        lines.append(
            f"| {r.severity_zh} | {r.reachable_zh} | {ns} | `{r.target.url}` | {r.middleware or '-'} "
            f"| {r.status_zh} | {evidence} |"
        )

    # ---------- 详细测试报告 ----------
    lines += [
        "",
        "## 详细测试报告",
        "",
        "按严重级别分组,展示每个目标的具体测试过程、请求/响应与结论。",
        "",
    ]

    for severity_key, title in (("critical", "🔴 严重漏洞"), ("high", "🟠 高危漏洞"),
                                 ("info", "⚪ 信息 / 待确认"), ("ok", "🟢 正常")):
        group = [r for r in results if r.severity.value == severity_key]
        if not group:
            continue
        lines += [f"### {title}({len(group)} 项)", ""]

        for r in sorted(group, key=lambda x: x.target.namespace):
            ns = r.target.namespace or "-"
            name = r.target.name or "-"
            lines += [
                f"#### [{ns} / {name}] {r.target.url}",
                "",
                f"- **中间件:** {r.middleware or '未识别'}",
                f"- **公网可达:** {r.reachable_zh}",
                f"- **判定:** {r.status_zh}",
                f"- **证据:** {'; '.join(r.evidence) or '-'}",
            ]
            if r.error:
                lines.append(f"- **错误信息:** {r.error}")
            lines.append("")

            if not r.details:
                lines += ["_(无测试详情)_", ""]
                continue

            lines += [
                "| 测试项 | 测试说明 | 使用的凭据 | 请求 | 响应结果 | 结论 |",
                "|---|---|---|---|---|---|",
            ]
            for d in r.details:
                lines.append(
                    f"| {d.name} | {_escape(d.description)} | {_escape(d.credentials)} "
                    f"| {_escape(d.request)} | {_escape(d.response)} | {_escape(d.result)} |"
                )
            lines.append("")

    lines.append("---")
    lines.append("*本报告由 ingress-exposure-checker 自动生成;仅默认凭据检测,不含爆破。*")
    return "\n".join(lines)
