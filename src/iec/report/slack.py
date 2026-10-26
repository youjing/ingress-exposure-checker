from __future__ import annotations

from datetime import datetime

import httpx

from iec.models import ScanResult, Severity

# Slack 单消息 block 上限 50: 3 固定(header/汇总/footer) + 每条告警 2 块 + 截断提示及分隔 2
MAX_FINDINGS = 22

SEVERITY_ICON = {
    Severity.CRITICAL: "🔴 严重 — 无需登录即可访问",
    Severity.HIGH: "🟠 高危 — 默认凭据可登录",
}


def env_name_from_file(path: str) -> str:
    """从输入文件名推导环境名: services.xxx.ingress.txt -> services.xxx"""
    from pathlib import Path
    name = Path(path).name
    suffix = ".ingress.txt"
    if name.endswith(suffix):
        return name[: -len(suffix)]
    return Path(path).stem


def _finding_blocks(r: ScanResult) -> list[dict]:
    from urllib.parse import urlparse
    host = urlparse(r.target.url).netloc
    # 取漏洞凭据(若有)
    creds = next(
        (d.credentials for d in r.details if d.vulnerable and d.credentials not in ("-", "")),
        "-",
    )
    evidence = "; ".join(r.evidence[:2]) or "-"
    blocks: list[dict] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{SEVERITY_ICON[r.severity]}*\n<{r.target.url}|{host}{urlparse(r.target.url).path}>",
            },
            "fields": [
                {"type": "mrkdwn", "text": f"*命名空间:*\n`{r.target.namespace or '-'}`"},
                {"type": "mrkdwn", "text": f"*中间件:*\n{r.middleware or '未识别'}"},
                {"type": "mrkdwn", "text": f"*使用的凭据:*\n`{creds}`"},
                {"type": "mrkdwn", "text": f"*证据:*\n{evidence}"},
            ],
        }
    ]
    return blocks


def build_slack_payload(results: list[ScanResult], env_name: str,
                        total_scanned: int, report_path: str = "report.html") -> dict:
    """构建 Slack Block Kit 卡片(仅严重/高危)。"""
    findings = [r for r in results
                if r.severity in (Severity.CRITICAL, Severity.HIGH)]
    findings.sort(key=lambda r: (r.severity != Severity.CRITICAL, r.target.namespace))

    critical = sum(1 for r in results if r.severity == Severity.CRITICAL)
    high = sum(1 for r in results if r.severity == Severity.HIGH)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    icon = "🚨" if critical else "⚠️"
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text",
                     "text": f"{icon} Ingress 暴露扫描告警 — {env_name}",
                     "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*扫描目标:* {total_scanned}  ·  *🔴 严重:* {critical}  ·  *🟠 高危:* {high}\n*完成时间:* {now}"},
        },
        {"type": "divider"},
    ]

    for r in findings[:MAX_FINDINGS]:
        blocks.extend(_finding_blocks(r))
        blocks.append({"type": "divider"})

    if len(findings) > MAX_FINDINGS:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"_另有 {len(findings) - MAX_FINDINGS} 条告警未展示, 详见完整报告..._"},
        })
        blocks.append({"type": "divider"})

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn",
                      "text": f"ingress-exposure-checker · 仅含严重/高危告警 · 完整报告: `{report_path}`"}],
    })

    summary = (f"Ingress 暴露扫描告警 [{env_name}]: "
               f"严重 {critical} / 高危 {high} (共扫描 {total_scanned})")
    return {"text": summary, "blocks": blocks}


async def send_slack(webhook_url: str, payload: dict) -> tuple[bool, str]:
    """POST Block Kit payload 到 Slack Incoming Webhook。"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
    except httpx.HTTPError as e:
        return False, f"发送失败: {type(e).__name__}: {e}"
    if resp.status_code == 200 and resp.text.strip() == "ok":
        return True, "已发送到 Slack"
    return False, f"Slack 返回 HTTP {resp.status_code}: {resp.text[:120]}"
