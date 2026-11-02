from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from iec.models import ScanResult, Severity

SEVERITY_AM: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
}


def _rfc3339(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def am_api_url(base: str) -> str:
    """AM base(可含反代前缀) -> /api/v2/alerts 完整地址。"""
    return base.rstrip("/") + "/api/v2/alerts"


def build_alerts(results: list[ScanResult], env_name: str,
                 ends_hours: float = 25.0) -> list[dict]:
    """每条严重/高危漏洞一个告警。排序: 严重在前, 同级按 namespace。"""
    findings = [r for r in results if r.severity in SEVERITY_AM]
    findings.sort(key=lambda r: (r.severity != Severity.CRITICAL,
                                 r.target.namespace))
    now = datetime.now(timezone.utc)
    ends = now + timedelta(hours=ends_hours)
    alerts: list[dict] = []
    for r in findings:
        creds = next((d.credentials for d in r.details
                      if d.vulnerable and d.credentials not in ("-", "")), None)
        description = "; ".join(r.evidence) or "-"
        if creds:
            description = f"[凭据: {creds}] {description}"
        alerts.append({
            "labels": {
                "alertname": "IngressExposure",
                "severity": SEVERITY_AM[r.severity],
                "instance": r.target.url,
                "namespace": r.target.namespace or "unknown",
                "middleware": r.middleware or "unknown",
                "env": env_name,
            },
            "annotations": {
                "summary": r.status_zh,
                "description": description,
            },
            "startsAt": _rfc3339(now),
            "endsAt": _rfc3339(ends),
        })
    return alerts


async def send_to_alertmanager(url: str, alerts: list[dict],
                               user: str | None = None,
                               password: str | None = None,
                               verify_tls: bool = True) -> tuple[bool, str]:
    """POST 告警到 Alertmanager /api/v2/alerts (Basic Auth 可选)。"""
    if not alerts:
        return True, "无严重/高危告警, 未发送"
    auth = (user, password) if user else None
    try:
        async with httpx.AsyncClient(timeout=10, verify=verify_tls) as client:
            resp = await client.post(url, json=alerts, auth=auth)
    except httpx.HTTPError as e:
        return False, f"发送失败: {type(e).__name__}: {e}"
    if resp.status_code == 200:
        return True, f"已发送 {len(alerts)} 条告警到 Alertmanager"
    return False, f"Alertmanager 返回 HTTP {resp.status_code}: {resp.text[:120]}"
